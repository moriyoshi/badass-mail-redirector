package uplooker

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func parseLiteralIP(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return ip.String()
}

type byName struct {
	addrs         []string
	canonicalName string
}

type hostsFileContent struct {
	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName map[string]byName

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string

	expiry time.Time
	mtime  time.Time
	size   int64
}

// hosts contains known host entries.
type HostsFileUplooker struct {
	sync.Mutex

	cacheMaxAge time.Duration
	path        string
	nowGetter   func() time.Time

	hosts atomic.Pointer[hostsFileContent]
}

var longLongAgo = time.Unix(0, 0)

func (u *HostsFileUplooker) readHosts(ctx context.Context) (hosts *hostsFileContent) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	now := u.nowGetter()
	hosts = u.hosts.Load()

	var fi os.FileInfo
	var statErr error
	if hosts != nil {
		if now.Before(hosts.expiry) && len(hosts.byName) > 0 {
			return
		}

		fi, statErr = os.Stat(u.path)
		// just refresh the expiry if the file exists and nothing seems to have changed
		if statErr == nil {
			if hosts.mtime.Equal(fi.ModTime()) && hosts.size == fi.Size() {
				hosts.expiry = now.Add(u.cacheMaxAge)
				return
			}
		} else {
			return
		}
	}

	u.Lock()
	defer u.Unlock()

	hs := make(map[string]byName)
	is := make(map[string][]string)

	f, err := os.Open(u.path)
	if err != nil {
		return
	}
	defer f.Close()

	go func() {
		<-ctx.Done()
		f.SetReadDeadline(longLongAgo)
	}()

	if fi == nil {
		fi, err = f.Stat()
		if err != nil {
			return
		}
	}

	eof := false
	for r := bufio.NewReader(f); !eof; {
		var line []byte
		for {
			l, pfx, err := r.ReadLine()
			if err != nil {
				if err == io.EOF {
					eof = true
					err = nil
				} else {
					return hosts
				}
			}
			line = append(line, l...)
			if !pfx {
				break
			}
		}
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := strings.Fields(string(line))
		if len(f) < 2 {
			continue
		}
		addr := parseLiteralIP(f[0])
		if addr == "" {
			continue
		}

		var canonical string
		for i := 1; i < len(f); i++ {
			name := absDomainName(f[i])
			key := absDomainName(strings.ToLower(f[i]))

			if i == 1 {
				canonical = key
			}

			is[addr] = append(is[addr], name)

			if v, ok := hs[key]; ok {
				hs[key] = byName{
					addrs:         append(v.addrs, addr),
					canonicalName: v.canonicalName,
				}
				continue
			}

			hs[key] = byName{
				addrs:         []string{addr},
				canonicalName: canonical,
			}
		}
	}
	// Update the data cache.
	hosts = &hostsFileContent{
		expiry: now.Add(u.cacheMaxAge),
		byName: hs,
		byAddr: is,
		mtime:  fi.ModTime(),
		size:   fi.Size(),
	}

	u.hosts.Store(hosts)
	return hosts
}

// lookupStaticHost looks up the addresses and the canonical name for the given host from /etc/hosts.
func (u *HostsFileUplooker) LookupHost(ctx context.Context, host string) ([]string, string) {
	u.Lock()
	defer u.Unlock()
	hosts := u.readHosts(ctx)
	if len(hosts.byName) != 0 {
		host = strings.ToLower(host)
		if byName, ok := hosts.byName[absDomainName(host)]; ok {
			ipsCp := make([]string, len(byName.addrs))
			copy(ipsCp, byName.addrs)
			return ipsCp, byName.canonicalName
		}
	}
	return nil, ""
}

// lookupStaticAddr looks up the hosts for the given address from /etc/hosts.
func (u *HostsFileUplooker) LookupAddr(ctx context.Context, addr string) []string {
	u.Lock()
	defer u.Unlock()
	hosts := u.readHosts(ctx)
	addr = parseLiteralIP(addr)
	if addr == "" {
		return nil
	}
	if len(hosts.byAddr) != 0 {
		if hosts, ok := hosts.byAddr[addr]; ok {
			hostsCp := make([]string, len(hosts))
			copy(hostsCp, hosts)
			return hostsCp
		}
	}
	return nil
}

type HostsFileUplookerOptionFunc func(*HostsFileUplooker) error

func WithNowGetter(f func() time.Time) HostsFileUplookerOptionFunc {
	return func(u *HostsFileUplooker) error {
		u.nowGetter = f
		return nil
	}
}

func WithCacheMaxAge(d time.Duration) HostsFileUplookerOptionFunc {
	return func(u *HostsFileUplooker) error {
		u.cacheMaxAge = d
		return nil
	}
}

func WithHostsFilePath(path string) HostsFileUplookerOptionFunc {
	return func(u *HostsFileUplooker) error {
		u.path = path
		return nil
	}
}

func NewHostsFileUplooker(options ...HostsFileUplookerOptionFunc) (*HostsFileUplooker, error) {
	u := &HostsFileUplooker{
		cacheMaxAge: 5 * time.Second,
		path:        GetDefaultHostsFilePath(),
		nowGetter:   time.Now,
	}
	for _, o := range options {
		err := o(u)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}

// absDomainName returns an absolute domain name which ends with a
// trailing dot to match pure Go reverse resolver and all other lookup
// routines.
// See golang.org/issue/12189.
// But we don't want to add dots for local names from /etc/hosts.
// It's hard to tell so we settle on the heuristic that names without dots
// (like "localhost" or "myhost") do not get trailing dots, but any other
// names do.
func absDomainName(s string) string {
	if strings.IndexByte(s, '.') != -1 && s[len(s)-1] != '.' {
		s += "."
	}
	return s
}
