package resolver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// DNSConfig holds DNS configuration.
type DNSConfig struct {
	Servers       []string      // name servers to use
	Search        []string      // rooted suffixes to append to local name
	Ndots         int           // number of dots in name to trigger absolute lookup
	Timeout       time.Duration // wait before giving up on a query, including retries
	Attempts      int           // lost packets before giving up on server
	Rotate        bool          // round robin among servers
	Lookup        []string      // OpenBSD top-level database "lookup" order
	SingleRequest bool          // use sequential A and AAAA queries instead of parallel queries
	UseTCP        bool          // force usage of TCP for DNS resolutions
	TrustAD       bool          // add AD flag to queries
	EDNS0         bool          // use EDNS0 extension
	NoReload      bool          // do not check for config file updates
}

// nameList returns a list of names for sequential DNS queries.
func (conf *DNSConfig) nameList(name string) []string {
	// Check name length (see isDomainName).
	l := len(name)
	rooted := l > 0 && name[l-1] == '.'
	if l > 254 || l == 254 && !rooted {
		return nil
	}

	// If name is rooted (trailing dot), try only that name.
	if rooted {
		if avoidDNS(name) {
			return nil
		}
		return []string{name}
	}

	hasNdots := strings.Count(name, ".") >= conf.Ndots
	name += "."
	l++

	// Build list of search choices.
	names := make([]string, 0, 1+len(conf.Search))
	// If name has enough dots, try unsuffixed first.
	if hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	// Try suffixes that are not too long (see isDomainName).
	for _, suffix := range conf.Search {
		fqdn := name + suffix
		if !avoidDNS(fqdn) && len(fqdn) <= 254 {
			names = append(names, fqdn)
		}
	}
	// Try unsuffixed, if not tried first above.
	if !hasNdots && !avoidDNS(name) {
		names = append(names, name)
	}
	return names
}

var dnsConfigProtoDefault = DNSConfig{
	Servers:  []string{"127.0.0.1:53", "[::1]:53"},
	Search:   dnsDefaultSearch(),
	Ndots:    1,
	Timeout:  5 * time.Second,
	Attempts: 2,
	EDNS0:    true,
}

func DefaultConfig() DNSConfig {
	return dnsConfigProtoDefault
}

type DNSConfigLoader func(ctx context.Context) (*DNSConfig, error)

var defaultConfigLoader DNSConfigLoader

func GetSystemDNSConfig(ctx context.Context) (*DNSConfig, error) {
	return defaultConfigLoader(ctx)
}

// A ResolvConfLoader loads name server configuration from resolv.conf.
type ResolvConfLoader struct {
	proto          DNSConfig        // read-only copy of the config
	nowGetter      func() time.Time // returns current time
	cacheMaxAge    time.Duration    // maximum time to cache the result of a successful read
	noReload       bool             // set to true to disable checks for updates to resolv.conf
	resolvConfPath string           // path to resolv.conf
	expiry         time.Time        // cache expiry time
	lastMtime      time.Time        // last modification time of resolv.conf

	// ch is used as a semaphore that only allows one lookup at a
	// time to recheck resolv.conf.
	ch chan struct{} // guards lastChecked and modTime

	dnsConfig atomic.Pointer[DNSConfig] // parsed resolv.conf structure used in lookups
}

func (loader *ResolvConfLoader) Prototype() DNSConfig {
	return loader.proto
}

// tryUpdate tries to update conf with the named resolv.conf file.
// The name variable only exists for testing. It is otherwise always
// "/etc/resolv.conf".
func (loader *ResolvConfLoader) Get(ctx context.Context) (*DNSConfig, error) {
	lastConfig := loader.dnsConfig.Load()
	now := loader.nowGetter()

	if lastConfig != nil && loader.noReload && lastConfig.NoReload {
		return lastConfig, nil
	}

	// Ensure only one update at a time checks resolv.conf.
	if !loader.tryAcquireSema(ctx) {
		return lastConfig, ctx.Err()
	}
	defer loader.releaseSema()

	// access to loader.expiry may race, so it needs to be inside the critical section.
	if lastConfig != nil {
		if now.Before(loader.expiry) {
			return lastConfig, nil
		}

		// cache expired, check mtime
		var mtime time.Time
		fi, err := os.Stat(loader.resolvConfPath)
		if err != nil {
			return lastConfig, nil
		}
		mtime = fi.ModTime()
		if mtime.Equal(loader.lastMtime) {
			loader.expiry = now.Add(loader.cacheMaxAge)
			return lastConfig, nil
		}
	}

	newConfig, mtime, err := loader.load(ctx)
	if err != nil {
		if lastConfig != nil {
			return lastConfig, nil
		}
		return nil, err
	}
	loader.expiry = now.Add(loader.cacheMaxAge)
	loader.lastMtime = mtime
	loader.dnsConfig.Store(newConfig)
	return newConfig, nil
}

type ResolverOptionFunc func(any) error

func WithResolvConfPath(path string) ResolverOptionFunc {
	return func(loader any) error {
		switch loader := (loader).(type) {
		case *ResolvConfLoader:
			loader.resolvConfPath = path
		default:
			return errors.New("unsupported loader type")
		}
		return nil
	}
}

func NewResolvConfLoader(options ...ResolverOptionFunc) (*ResolvConfLoader, error) {
	loader := &ResolvConfLoader{
		proto:          dnsConfigProtoDefault,
		nowGetter:      time.Now,
		cacheMaxAge:    5 * time.Second,
		noReload:       false,
		resolvConfPath: "/etc/resolv.conf",
		ch:             make(chan struct{}, 1),
	}
	for _, fn := range options {
		err := fn(loader)
		if err != nil {
			return nil, err
		}
	}
	return loader, nil
}

func (loader *ResolvConfLoader) tryAcquireSema(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case loader.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (loader *ResolvConfLoader) releaseSema() {
	<-loader.ch
}

var longLongAgo = time.Unix(0, 0)

// See resolv.conf(5) on a Linux machine.
func (loader *ResolvConfLoader) load(ctx context.Context) (retval *DNSConfig, mtime time.Time, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dnsConf := loader.proto
	f, err := os.Open(loader.resolvConfPath)
	if err != nil {
		return
	}
	defer f.Close()
	go func() {
		<-ctx.Done()
		f.SetReadDeadline(longLongAgo)
	}()
	fi, err := f.Stat()
	if err != nil {
		return
	}
	mtime = fi.ModTime()
	r := bufio.NewReader(f)
	var eof bool
	for !eof {
		var line []byte
		var pfx bool
		for {
			var l []byte
			l, pfx, err = r.ReadLine()
			if err != nil {
				if err == io.EOF {
					eof = true
					err = nil
				} else {
					return
				}
			}
			if !pfx {
				break
			}
			line = append(line, l...)
		}
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			// comment.
			continue
		}
		fields := getFields(string(line))
		if len(fields) < 1 {
			continue
		}
		switch fields[0] {
		case "nameserver": // add one name server
			if len(fields) > 1 && len(dnsConf.Servers) < 3 { // small, but the standard limit
				// One more check: make sure server name is
				// just an IP address. Otherwise we need DNS
				// to look it up.
				if _, err := netip.ParseAddr(string(fields[1])); err == nil {
					dnsConf.Servers = append(dnsConf.Servers, net.JoinHostPort(string(fields[1]), "53"))
				}
			}

		case "domain": // set search path to just this domain
			if len(fields) > 1 {
				dnsConf.Search = []string{ensureRooted(string(fields[1]))}
			}

		case "search": // set search path to given servers
			dnsConf.Search = make([]string, 0, len(fields)-1)
			for i := 1; i < len(fields); i++ {
				name := ensureRooted(string(fields[i]))
				if name == "." {
					continue
				}
				dnsConf.Search = append(dnsConf.Search, name)
			}

		case "options": // magic options
			for _, s := range fields[1:] {
				i := strings.IndexByte(s, ':')
				if i < 0 {
					i = len(s)
				}
				switch s[:i] {
				case "ndots":
					n, _, _ := dtoi(s[i+1:])
					if n < 0 {
						n = 0
					} else if n > 15 {
						n = 15
					}
					dnsConf.Ndots = n
				case "timeout":
					n, _, _ := dtoi(s[i+1:])
					if n < 1 {
						n = 1
					}
					dnsConf.Timeout = time.Duration(n) * time.Second
				case "attempts":
					n, _, _ := dtoi(s[i+1:])
					if n < 1 {
						n = 1
					}
					dnsConf.Attempts = n
				case "rotate":
					if i != len(s) {
						break
					}
					dnsConf.Rotate = true
				case "single-request", "single-request-reopen":
					if i != len(s) {
						break
					}
					// Linux option:
					// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
					// "By default, glibc performs IPv4 and IPv6 lookups in parallel [...]
					//  This option disables the behavior and makes glibc
					//  perform the IPv6 and IPv4 requests sequentially."
					dnsConf.SingleRequest = true
				case "use-vc", "usevc", "tcp":
					if i != len(s) {
						break
					}
					// Linux (use-vc), FreeBSD (usevc) and OpenBSD (tcp) option:
					// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
					// "Sets RES_USEVC in _res.options.
					//  This option forces the use of TCP for DNS resolutions."
					// https://www.freebsd.org/cgi/man.cgi?query=resolv.conf&sektion=5&manpath=freebsd-release-ports
					// https://man.openbsd.org/resolv.conf.5
					dnsConf.UseTCP = true
				case "trust-ad":
					if i != len(s) {
						break
					}
					dnsConf.TrustAD = true
				case "edns0":
					if i != len(s) {
						break
					}
					dnsConf.EDNS0 = true
				case "no-reload":
					if i != len(s) {
						break
					}
					dnsConf.NoReload = true
				}
			}

		case "lookup":
			// OpenBSD option:
			// https://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man5/resolv.conf.5
			// "the legal space-separated values are: bind, file, yp"
			dnsConf.Lookup = fields[1:]
		}
	}

	retval = new(DNSConfig)
	*retval = dnsConf
	return
}

var getHostname = os.Hostname // variable for testing

func dnsDefaultSearch() []string {
	hn, err := getHostname()
	if err != nil {
		// best effort
		return nil
	}
	if i := strings.IndexByte(hn, '.'); i >= 0 && i < len(hn)-1 {
		return []string{ensureRooted(hn[i+1:])}
	}
	return nil
}

func ensureRooted(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s
	}
	return s + "."
}

func getFields(s string) []string { return strings.Fields(s) }

func init() {
	OptionFuncHooks.CacheMaxAge = OptionFuncHooks.CacheMaxAge.Add(func(loader any, value time.Duration) (bool, error) {
		if loader, ok := (loader).(*ResolvConfLoader); ok {
			loader.cacheMaxAge = value
			return true, nil
		}
		return false, nil
	})
	OptionFuncHooks.NowGetter = OptionFuncHooks.NowGetter.Add(func(loader any, value func() time.Time) (bool, error) {
		if loader, ok := (loader).(*ResolvConfLoader); ok {
			loader.nowGetter = value
			return true, nil
		}
		return false, nil
	})
	OptionFuncHooks.NoReload = OptionFuncHooks.NoReload.Add(func(loader any, value bool) (bool, error) {
		if loader, ok := (loader).(*ResolvConfLoader); ok {
			loader.noReload = value
			return true, nil
		}
		return false, nil
	})
}
