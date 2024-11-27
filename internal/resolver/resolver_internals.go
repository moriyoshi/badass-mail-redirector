// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// DNS client: see RFC 1035.
// Has to be linked into package net for Dial.

// TODO(rsc):
//	Could potentially handle many outstanding lookups faster.
//	Random UDP source port (net.Dial should do that for us).
//	Random request IDs.

package resolver

import (
	"cmp"
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// Maximum DNS packet size.
	// Value taken from https://dnsflagday.net/2020/.
	maxDNSPacketSize = 1232
)

func (r *Resolver) servers(cfg *DNSConfig) ([]string, int) {
	var i uint32
	if cfg.Rotate {
		i = atomic.AddUint32(&r.soffset, 1) - 1 // return 0 to start
	}
	return cfg.Servers, int(i)

}

func (r *Resolver) now() time.Time {
	if r.nowGetter != nil {
		return r.nowGetter()
	}
	return time.Now()
}

// dial makes a new connection to the provided server (which must be
// an IP address) with the provided network type, using either r.Dial
// (if both r and r.Dial are non-nil) or else Dialer.DialContext.
func (r *Resolver) dial(ctx context.Context, network, server string) (net.Conn, error) {
	// Calling Dial here is scary -- we have to be sure not to
	// dial a name that will require a DNS lookup, or Dial will
	// call back here to translate it. The DNS config parser has
	// already checked that all the cfg.servers are IP
	// addresses, which Dial will use without a DNS lookup.
	var c net.Conn
	var err error
	if r != nil && r.Dial != nil {
		c, err = r.Dial(ctx, network, server)
	} else {
		var d net.Dialer
		c, err = d.DialContext(ctx, network, server)
	}
	if err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

func (r *Resolver) staticLookup(ctx context.Context, name string) ([]string, string) {
	if r.uplooker == nil {
		return nil, ""
	}
	return r.uplooker.LookupHost(ctx, name)
}

func (r *Resolver) staticLookupAddr(ctx context.Context, addr string) []string {
	if r.uplooker == nil {
		return nil
	}
	return r.uplooker.LookupAddr(ctx, addr)
}

func (r *Resolver) newRequest(conf *DNSConfig, q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = uint16(rand.Intn(65536))
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: conf.TrustAD})
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}

	if !r.avoidEDNS0 && conf.EDNS0 {
		// Accept packets up to maxDNSPacketSize.  RFC 6891.
		if err := b.StartAdditionals(); err != nil {
			return 0, nil, nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(maxDNSPacketSize, dnsmessage.RCodeSuccess, false); err != nil {
			return 0, nil, nil, err
		}
		if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
			return 0, nil, nil, err
		}
	}

	tcpReq, err = b.Finish()
	if err != nil {
		return 0, nil, nil, err
	}
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, nil
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, maxDNSPacketSize)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		// Ignore invalid responses as they may be malicious
		// forgery attempts. Instead continue waiting until
		// timeout. See golang.org/issue/13281.
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}

	b = make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, ErrCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, ErrCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, ErrInvalidDNSResponse
	}
	return p, h, nil
}

// exchange sends a query on the connection and hopes for a response.
func (r *Resolver) exchange(ctx context.Context, cfg *DNSConfig, server string, q dnsmessage.Question) (dnsmessage.Parser, dnsmessage.Header, error) {
	q.Class = dnsmessage.ClassINET
	id, udpReq, tcpReq, err := r.newRequest(cfg, q)
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, ErrCannotMarshalDNSMessage
	}
	var networks []string
	if cfg.UseTCP {
		networks = []string{"tcp"}
	} else {
		networks = []string{"udp", "tcp"}
	}
	for _, network := range networks {
		ctx, cancel := context.WithDeadline(ctx, r.now().Add(cfg.Timeout))
		defer cancel()

		c, err := r.dial(ctx, network, server)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			c.SetDeadline(d)
		}
		var p dnsmessage.Parser
		var h dnsmessage.Header
		if _, ok := c.(net.PacketConn); ok {
			p, h, err = dnsPacketRoundTrip(c, id, q, udpReq)
		} else {
			p, h, err = dnsStreamRoundTrip(c, id, q, tcpReq)
		}
		c.Close()
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, mapErr(err)
		}
		if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
			return dnsmessage.Parser{}, dnsmessage.Header{}, ErrInvalidDNSResponse
		}
		// RFC 5966 indicates that when a client receives a UDP response with
		// the TC flag set, it should take the TC flag as an indication that it
		// should retry over TCP instead.
		// The case when the TC flag is set in a TCP response is not well specified,
		// so this implements the glibc resolver behavior, returning the existing
		// dns response instead of returning a "errNoAnswerFromDNSServer" error.
		// See go.dev/issue/64896
		if h.Truncated && network == "udp" {
			continue
		}
		return p, h, nil
	}
	return dnsmessage.Parser{}, dnsmessage.Header{}, ErrNoAnswerFromDNSServer
}

// checkHeader performs basic sanity checks on the header.
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	rcode, hasAdd := extractExtendedRCode(*p, h)

	if rcode == dnsmessage.RCodeNameError {
		return ErrNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return ErrCannotUnmarshalDNSMessage
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if rcode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone && !hasAdd {
		return ErrLameReferral
	}

	if rcode != dnsmessage.RCodeSuccess && rcode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if rcode == dnsmessage.RCodeServerFailure {
			return ErrServerTemporarilyMisbehaving
		}
		return ErrServerMisbehaving
	}

	return nil
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return ErrNoSuchHost
		}
		if err != nil {
			return ErrCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return ErrCannotUnmarshalDNSMessage
		}
	}
}

// extractExtendedRCode extracts the extended RCode from the OPT resource (EDNS(0))
// If an OPT record is not found, the RCode from the hdr is returned.
// Another return value indicates whether an additional resource was found.
func extractExtendedRCode(p dnsmessage.Parser, hdr dnsmessage.Header) (dnsmessage.RCode, bool) {
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	hasAdd := false
	for {
		ahdr, err := p.AdditionalHeader()
		if err != nil {
			return hdr.RCode, hasAdd
		}
		hasAdd = true
		if ahdr.Type == dnsmessage.TypeOPT {
			return ahdr.ExtendedRCode(hdr.RCode), hasAdd
		}
		if err := p.SkipAdditional(); err != nil {
			return hdr.RCode, hasAdd
		}
	}
}

// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func (r *Resolver) tryOneName(ctx context.Context, cfg *DNSConfig, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	var lastErr error

	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Parser{}, "", &net.DNSError{Err: ErrCannotMarshalDNSMessage.Error(), Name: name}
	}
	q := dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}

	servers, offset := r.servers(cfg)

	for i := 0; i < cfg.Attempts; i++ {
		for j := 0; j < len(servers); j++ {
			server := servers[(offset+j)%len(servers)]

			p, h, err := r.exchange(ctx, cfg, server, q)
			if err != nil {
				dnsErr := &net.DNSError{Err: err.Error(), Name: name, Server: server}
				// Set IsTemporary for socket-level errors. Note that this flag
				// may also be used to indicate a SERVFAIL response.
				if _, ok := err.(*net.OpError); ok {
					dnsErr.IsTemporary = true
				}
				lastErr = dnsErr
				continue
			}

			if err := checkHeader(&p, h); err != nil {
				dnsErr := &net.DNSError{Err: err.Error(), Name: name, Server: server}
				if err == ErrNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, dnsErr
				}
				lastErr = dnsErr
				continue
			}

			if err := skipToAnswer(&p, qtype); err != nil {
				dnsErr := &net.DNSError{Err: err.Error(), Name: name, Server: server}
				if err == ErrNoSuchHost {
					// The name does not exist, so trying
					// another server won't help.
					return p, server, dnsErr
				}
				lastErr = dnsErr
				continue
			}

			return p, server, nil
		}
	}
	return dnsmessage.Parser{}, "", lastErr
}

func (r *Resolver) lookup(ctx context.Context, conf *DNSConfig, name string, qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {
	if !isDomainName(name) {
		// We used to use "invalid domain name" as the error,
		// but that is a detail of the specific lookup mechanism.
		// Other lookups might allow broader name syntax
		// (for example Multicast DNS allows UTF-8; see RFC 6762).
		// For consistency with libc resolvers, report no such host.
		return dnsmessage.Parser{}, "", &net.DNSError{Err: ErrNoSuchHost.Error(), Name: name}
	}

	var (
		p      dnsmessage.Parser
		server string
		err    error
	)
	for _, fqdn := range conf.nameList(name) {
		p, server, err = r.tryOneName(ctx, conf, fqdn, qtype)
		if err == nil {
			break
		}
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() && r.StrictErrors {
			// If we hit a temporary error with StrictErrors enabled,
			// stop immediately instead of trying more names.
			break
		}
	}
	if err == nil {
		return p, server, nil
	}
	if err, ok := err.(*net.DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		err.Name = name
	}
	return dnsmessage.Parser{}, "", err
}

func domainSuffix(name string) string {
	if len(name) == 0 {
		return ""
	}
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	i := strings.LastIndexByte(name, '.')
	if i == -1 {
		return ""
	}
	return name[i:]
}

// avoidDNS reports whether this is a hostname for which we should not
// use DNS. Currently this includes only .onion, per RFC 7686. See
// golang.org/issue/13705. Does not cover .local names (RFC 6762),
// see golang.org/issue/16739.
func avoidDNS(name string) bool {
	suffix := domainSuffix(name)
	if suffix == "" {
		return true
	}
	return strings.EqualFold(suffix, ".onion")
}

func (r *Resolver) goLookupIPCNAMEDNS(ctx context.Context, conf *DNSConfig, network, name string) (addrs []net.IPAddr, cname dnsmessage.Name, err error) {
	if !isDomainName(name) {
		// See comment in func lookup above about use of errNoSuchHost.
		return nil, dnsmessage.Name{}, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: name}
	}
	type result struct {
		p      dnsmessage.Parser
		server string
		error
	}

	lane := make(chan result, 1)
	qtypes := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	if network == "CNAME" {
		qtypes = append(qtypes, dnsmessage.TypeCNAME)
	}
	switch ipVersion(network) {
	case '4':
		qtypes = []dnsmessage.Type{dnsmessage.TypeA}
	case '6':
		qtypes = []dnsmessage.Type{dnsmessage.TypeAAAA}
	}
	var queryFn func(fqdn string, qtype dnsmessage.Type)
	var responseFn func(fqdn string, qtype dnsmessage.Type) result
	if conf.SingleRequest {
		queryFn = func(fqdn string, qtype dnsmessage.Type) {}
		responseFn = func(fqdn string, qtype dnsmessage.Type) result {
			r.wg.Add(1)
			defer r.wg.Done()
			p, server, err := r.tryOneName(ctx, conf, fqdn, qtype)
			return result{p, server, err}
		}
	} else {
		queryFn = func(fqdn string, qtype dnsmessage.Type) {
			r.wg.Add(1)
			go func(qtype dnsmessage.Type) {
				p, server, err := r.tryOneName(ctx, conf, fqdn, qtype)
				lane <- result{p, server, err}
				r.wg.Done()
			}(qtype)
		}
		responseFn = func(_ string, _ dnsmessage.Type) result {
			return <-lane
		}
	}
	var lastErr error
	for _, fqdn := range conf.nameList(name) {
		for _, qtype := range qtypes {
			queryFn(fqdn, qtype)
		}
		hitStrictError := false
		for _, qtype := range qtypes {
			result := responseFn(fqdn, qtype)
			if result.error != nil {
				if nerr, ok := result.error.(net.Error); ok && nerr.Temporary() && r.StrictErrors {
					// This error will abort the nameList loop.
					hitStrictError = true
					lastErr = result.error
				} else if lastErr == nil || fqdn == name+"." {
					// Prefer error for original name.
					lastErr = result.error
				}
				continue
			}

			// Presotto says it's okay to assume that servers listed in
			// /etc/resolv.conf are recursive resolvers.
			//
			// We asked for recursion, so it should have included all the
			// answers we need in this one packet.
			//
			// Further, RFC 1034 section 4.3.1 says that "the recursive
			// response to a query will be... The answer to the query,
			// possibly preface by one or more CNAME RRs that specify
			// aliases encountered on the way to an answer."
			//
			// Therefore, we should be able to assume that we can ignore
			// CNAMEs and that the A and AAAA records we requested are
			// for the canonical name.

		loop:
			for {
				h, err := result.p.AnswerHeader()
				if err != nil && err != dnsmessage.ErrSectionDone {
					lastErr = &net.DNSError{
						Err:    ErrCannotUnmarshalDNSMessage.Error(),
						Name:   name,
						Server: result.server,
					}
				}
				if err != nil {
					break
				}
				switch h.Type {
				case dnsmessage.TypeA:
					a, err := result.p.AResource()
					if err != nil {
						lastErr = &net.DNSError{
							Err:    ErrCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					addrs = append(addrs, net.IPAddr{IP: net.IP(a.A[:])})
					if cname.Length == 0 && h.Name.Length != 0 {
						cname = h.Name
					}

				case dnsmessage.TypeAAAA:
					aaaa, err := result.p.AAAAResource()
					if err != nil {
						lastErr = &net.DNSError{
							Err:    ErrCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					addrs = append(addrs, net.IPAddr{IP: net.IP(aaaa.AAAA[:])})
					if cname.Length == 0 && h.Name.Length != 0 {
						cname = h.Name
					}

				case dnsmessage.TypeCNAME:
					c, err := result.p.CNAMEResource()
					if err != nil {
						lastErr = &net.DNSError{
							Err:    ErrCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					if cname.Length == 0 && c.CNAME.Length > 0 {
						cname = c.CNAME
					}

				default:
					if err := result.p.SkipAnswer(); err != nil {
						lastErr = &net.DNSError{
							Err:    ErrCannotUnmarshalDNSMessage.Error(),
							Name:   name,
							Server: result.server,
						}
						break loop
					}
					continue
				}
			}
		}
		if hitStrictError {
			// If either family hit an error with StrictErrors enabled,
			// discard all addresses. This ensures that network flakiness
			// cannot turn a dualstack hostname IPv4/IPv6-only.
			addrs = nil
			break
		}
		if len(addrs) > 0 || network == "CNAME" && cname.Length > 0 {
			break
		}
	}
	if lastErr, ok := lastErr.(*net.DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		lastErr.Name = name
	}
	sortByRFC6724(addrs)
	return addrs, cname, lastErr
}

// goLookupPTR is the native Go implementation of LookupAddr.
func (r *Resolver) goLookupPTRDNS(ctx context.Context, conf *DNSConfig, addr string) ([]string, error) {
	arpa, err := reverseaddr(addr)
	if err != nil {
		return nil, err
	}
	p, server, err := r.lookup(ctx, conf, arpa, dnsmessage.TypePTR)
	if err != nil {
		return nil, err
	}
	var ptrs []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{
				Err:    ErrCannotUnmarshalDNSMessage.Error(),
				Name:   addr,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypePTR {
			err := p.SkipAnswer()
			if err != nil {
				return nil, &net.DNSError{
					Err:    ErrCannotUnmarshalDNSMessage.Error(),
					Name:   addr,
					Server: server,
				}
			}
			continue
		}
		ptr, err := p.PTRResource()
		if err != nil {
			return nil, &net.DNSError{
				Err:    ErrCannotUnmarshalDNSMessage.Error(),
				Name:   addr,
				Server: server,
			}
		}
		ptrs = append(ptrs, ptr.PTR.String())

	}

	return ptrs, nil
}

// goLookupSRV returns the SRV records for a target name, built either
// from its component service ("sip"), protocol ("tcp"), and name
// ("example.com."), or from name directly (if service and proto are
// both empty).
//
// In either case, the returned target name ("_sip._tcp.example.com.")
// is also returned on success.
//
// The records are sorted by weight.
func (r *Resolver) goLookupSRV(ctx context.Context, conf *DNSConfig, service, proto, name string) (target string, srvs []*net.SRV, err error) {
	if service == "" && proto == "" {
		target = name
	} else {
		target = "_" + service + "._" + proto + "." + name
	}
	p, server, err := r.lookup(ctx, conf, target, dnsmessage.TypeSRV)
	if err != nil {
		return "", nil, err
	}
	var cname dnsmessage.Name
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return "", nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeSRV {
			if err := p.SkipAnswer(); err != nil {
				return "", nil, &net.DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		if cname.Length == 0 && h.Name.Length != 0 {
			cname = h.Name
		}
		srv, err := p.SRVResource()
		if err != nil {
			return "", nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		srvs = append(srvs, &net.SRV{Target: srv.Target.String(), Port: srv.Port, Priority: srv.Priority, Weight: srv.Weight})
	}
	byPriorityWeight(srvs).sort()
	return cname.String(), srvs, nil
}

// goLookupMX returns the MX records for name.
func (r *Resolver) goLookupMX(ctx context.Context, conf *DNSConfig, name string) ([]*net.MX, error) {
	p, server, err := r.lookup(ctx, conf, name, dnsmessage.TypeMX)
	if err != nil {
		return nil, err
	}
	var mxs []*net.MX
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeMX {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		mx, err := p.MXResource()
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		mxs = append(mxs, &net.MX{Host: mx.MX.String(), Pref: mx.Pref})

	}
	byPref(mxs).sort()
	return mxs, nil
}

// goLookupNS returns the NS records for name.
func (r *Resolver) goLookupNS(ctx context.Context, conf *DNSConfig, name string) ([]*net.NS, error) {
	p, server, err := r.lookup(ctx, conf, name, dnsmessage.TypeNS)
	if err != nil {
		return nil, err
	}
	var nss []*net.NS
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeNS {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		ns, err := p.NSResource()
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		nss = append(nss, &net.NS{Host: ns.NS.String()})
	}
	return nss, nil
}

// goLookupTXT returns the TXT records from name.
func (r *Resolver) goLookupTXT(ctx context.Context, config *DNSConfig, name string) ([]string, error) {
	p, server, err := r.lookup(ctx, config, name, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	var txts []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		if h.Type != dnsmessage.TypeTXT {
			if err := p.SkipAnswer(); err != nil {
				return nil, &net.DNSError{
					Err:    "cannot unmarshal DNS message",
					Name:   name,
					Server: server,
				}
			}
			continue
		}
		txt, err := p.TXTResource()
		if err != nil {
			return nil, &net.DNSError{
				Err:    "cannot unmarshal DNS message",
				Name:   name,
				Server: server,
			}
		}
		// Multiple strings in one TXT record need to be
		// concatenated without separator to be consistent
		// with previous Go resolver.
		n := 0
		for _, s := range txt.TXT {
			n += len(s)
		}
		txtJoin := make([]byte, 0, n)
		for _, s := range txt.TXT {
			txtJoin = append(txtJoin, s...)
		}
		if len(txts) == 0 {
			txts = make([]string, 0, 1)
		}
		txts = append(txts, string(txtJoin))
	}
	return txts, nil
}

func (r *Resolver) goLookupHostOrder(ctx context.Context, conf *DNSConfig, name string, order HostLookupOrder) (addrs []string, err error) {
	ips, _, err := r.goLookupIPCNAMEOrder(ctx, conf, "ip", name, order)
	if err != nil {
		return
	}
	addrs = make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	return
}

// lookup entries from /etc/hosts
func (r *Resolver) goLookupIPFiles(ctx context.Context, name string) (addrs []net.IPAddr, canonical string) {
	addr, canonical := r.staticLookup(ctx, name)
	for _, haddr := range addr {
		haddr, zone := splitHostZone(haddr)
		if ip := net.ParseIP(haddr); ip != nil {
			addr := net.IPAddr{IP: ip, Zone: zone}
			addrs = append(addrs, addr)
		}
	}
	sortByRFC6724(addrs)
	return addrs, canonical
}

// goLookupIPOrder is the native Go implementation of LookupIP.
func (r *Resolver) goLookupIPCNAMEOrder(ctx context.Context, conf *DNSConfig, network, host string, order HostLookupOrder) (addrs []net.IPAddr, cname string, err error) {
	if order == HostLookupFilesDNS || order == HostLookupFiles {
		addrs, cname = r.goLookupIPFiles(ctx, host)
		if len(addrs) > 0 {
			return
		}
		if order == HostLookupFiles {
			err = &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host}
			return
		}
	}

	addrs, _cname, err := r.goLookupIPCNAMEDNS(ctx, conf, network, host)
	if err != nil {
		if order != HostLookupDNSFiles {
			return
		}
	} else {
		cname = _cname.String()
	}

	if len(addrs) == 0 && !(network == "CNAME" && _cname.Length > 0) && order == HostLookupDNSFiles {
		addrs, cname = r.goLookupIPFiles(ctx, host)
		if len(addrs) > 0 {
			err = nil
		}
	}
	return
}

// goLookupCNAME is the native Go (non-cgo) implementation of LookupCNAME.
func (r *Resolver) goLookupCNAMEOrder(ctx context.Context, conf *DNSConfig, host string, order HostLookupOrder) (string, error) {
	_, cname, err := r.goLookupIPCNAMEOrder(ctx, conf, "CNAME", host, order)
	return cname, err
}

// goLookupPTR is the native Go implementation of LookupAddr.
func (r *Resolver) goLookupPTROrder(ctx context.Context, conf *DNSConfig, addr string, order HostLookupOrder) ([]string, error) {
	if order == HostLookupFiles || order == HostLookupFilesDNS {
		names := r.staticLookupAddr(ctx, addr)
		if len(names) > 0 {
			return names, nil
		}

		if order == HostLookupFiles {
			return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: addr}
		}
	}

	names, err := r.goLookupPTRDNS(ctx, conf, addr)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			if order == HostLookupDNSFiles {
				names := r.staticLookupAddr(ctx, addr)
				if len(names) > 0 {
					return names, nil
				}
			}
		}
		return nil, err
	}

	return names, nil
}

// lookupIPReturn turns the return values from singleflight.Do into
// the return values from LookupIP.
func lookupIPReturn(addrsi any, err error, shared bool) ([]net.IPAddr, error) {
	if err != nil {
		return nil, err
	}
	addrs := addrsi.([]net.IPAddr)
	if shared {
		clone := make([]net.IPAddr, len(addrs))
		copy(clone, addrs)
		addrs = clone
	}
	return addrs, nil
}

// lookupIPAddr looks up host using the local resolver and particular network.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (r *Resolver) lookupIPAddr(ctx context.Context, conf *DNSConfig, network, host string, order HostLookupOrder) ([]net.IPAddr, error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host, Server: ""}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []net.IPAddr{{IP: net.IP(ip.AsSlice()).To16(), Zone: ip.Zone()}}, nil
	}
	// We don't want a cancellation of ctx to affect the
	// lookupGroup operation. Otherwise if our context gets
	// canceled it might cause an error to be returned to a lookup
	// using a completely different context. However we need to preserve
	// only the values in context. See Issue 28600.
	lookupGroupCtx, lookupGroupCancel := context.WithCancel(withUnexpiredValuesPreserved(ctx))

	lookupKey := network + "\000" + host
	r.wg.Add(1)
	ch := r.lookupGroup.DoChan(lookupKey, func() (any, error) {
		ips, _, err := r.goLookupIPCNAMEOrder(lookupGroupCtx, conf, network, host, order)
		return ips, err
	})

	select {
	case <-ctx.Done():
		<-ch
		r.wg.Done()
		lookupGroupCancel()
		return nil, ctx.Err()
	case p := <-ch:
		r.wg.Done()
		lookupGroupCancel()
		err := p.Err
		if err != nil {
			if _, ok := err.(*net.DNSError); !ok {
				err = &net.DNSError{Err: mapErr(err).Error(), Name: host, Server: ""}
			}
		}
		return lookupIPReturn(p.Val, err, p.Shared)
	}
}

// internetAddrList resolves addr, which may be a literal IP
// address or a DNS name, and returns a list of internet protocol
// family addresses. The result contains at least one address when
// error is nil.
func (r *Resolver) internetAddrList(ctx context.Context, conf *DNSConfig, network, addr string, order HostLookupOrder) ([]net.Addr, error) {
	var (
		err        error
		host, port string
		portnum    int
	)
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if addr != "" {
			if host, port, err = net.SplitHostPort(addr); err != nil {
				return nil, err
			}
			if portnum, err = r.LookupPort(ctx, network, port); err != nil {
				return nil, err
			}
		}
	case "ip", "ip4", "ip6":
		if addr != "" {
			host = addr
		}
	default:
		return nil, net.UnknownNetworkError(network)
	}
	inetaddr := func(ip net.IPAddr) net.Addr {
		switch network {
		case "tcp", "tcp4", "tcp6":
			return &net.TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "udp", "udp4", "udp6":
			return &net.UDPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "ip", "ip4", "ip6":
			return &net.IPAddr{IP: ip.IP, Zone: ip.Zone}
		default:
			panic("unexpected network: " + network)
		}
	}
	if host == "" {
		return []net.Addr{inetaddr(net.IPAddr{})}, nil
	}

	// Try as a literal IP address, then as a DNS name.
	ips, err := r.lookupIPAddr(ctx, conf, network, addr, order)
	if err != nil {
		return nil, err
	}
	// Issue 18806: if the machine has halfway configured
	// IPv6 such that it can bind on "::" (IPv6unspecified)
	// but not connect back to that same address, fall
	// back to dialing 0.0.0.0.
	if len(ips) == 1 && ips[0].IP.Equal(net.IPv6unspecified) {
		ips = append(ips, net.IPAddr{IP: net.IPv4zero})
	}

	var filter func(net.IPAddr) bool
	if len(network) > 0 && network[len(network)-1] == '4' {
		filter = func(addr net.IPAddr) bool { return addr.IP.To4() != nil }
	}
	if len(network) > 0 && network[len(network)-1] == '6' {
		filter = func(addr net.IPAddr) bool {
			return len(addr.IP) == net.IPv6len && addr.IP.To4() == nil
		}
	}
	return filterAddrList(filter, ips, inetaddr, host)
}

// filterAddrList applies a filter to a list of IP addresses,
// yielding a list of Addr objects. Known filters are nil, ipv4only,
// and ipv6only. It returns every address when the filter is nil.
// The result contains at least one address when error is nil.
func filterAddrList(filter func(net.IPAddr) bool, ips []net.IPAddr, inetaddr func(net.IPAddr) net.Addr, originalAddr string) ([]net.Addr, error) {
	var addrs []net.Addr
	for _, ip := range ips {
		if filter == nil || filter(ip) {
			addrs = append(addrs, inetaddr(ip))
		}
	}
	if len(addrs) == 0 {
		return nil, &net.AddrError{Err: ErrNoSuitableAddress.Error(), Addr: originalAddr}
	}
	return addrs, nil
}

// onlyValuesCtx is a context that uses an underlying context
// for value lookup if the underlying context hasn't yet expired.
type onlyValuesCtx struct {
	context.Context
	lookupValues context.Context
}

var _ context.Context = (*onlyValuesCtx)(nil)

// Value performs a lookup if the original context hasn't expired.
func (ovc *onlyValuesCtx) Value(key any) any {
	select {
	case <-ovc.lookupValues.Done():
		return nil
	default:
		return ovc.lookupValues.Value(key)
	}
}

// withUnexpiredValuesPreserved returns a context.Context that only uses lookupCtx
// for its values, otherwise it is never canceled and has no deadline.
// If the lookup context expires, any looked up values will return nil.
// See Issue 28600.
func withUnexpiredValuesPreserved(lookupCtx context.Context) context.Context {
	return &onlyValuesCtx{Context: context.Background(), lookupValues: lookupCtx}
}

// reverseaddr returns the in-addr.arpa. or ip6.arpa. hostname of the IP
// address addr suitable for rDNS (PTR) record lookup or an error if it fails
// to parse the IP address.
func reverseaddr(addr string) (arpa string, err error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", &net.DNSError{Err: "unrecognized address", Name: addr}
	}
	if ip.To4() != nil {
		buf := make([]byte, 0, 4*4+len("in-addr.arpa."))
		buf = strconv.AppendInt(buf, int64(ip[15]), 10)
		buf = append(buf, '.')
		buf = strconv.AppendInt(buf, int64(ip[14]), 10)
		buf = append(buf, '.')
		buf = strconv.AppendInt(buf, int64(ip[13]), 10)
		buf = append(buf, '.')
		buf = strconv.AppendInt(buf, int64(ip[12]), 10)
		buf = append(buf, ".in-addr.arpa."...)
		return string(buf), nil
	}
	// Must be IPv6
	buf := make([]byte, 0, len(ip)*4+len("ip6.arpa."))
	// Add it, in reverse, to the buffer
	for i := len(ip) - 1; i >= 0; i-- {
		v := ip[i]
		buf = append(buf, hexDigit[v&0xF],
			'.',
			hexDigit[v>>4],
			'.')
	}
	// Append "ip6.arpa." and return (buf already has the final .)
	buf = append(buf, "ip6.arpa."...)
	return string(buf), nil
}

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func isDomainName(s string) bool {
	// The root domain name is valid. See golang.org/issue/45715.
	if s == "." {
		return true
	}

	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}

// byPriorityWeight sorts SRV records by ascending priority and weight.
type byPriorityWeight []*net.SRV

// shuffleByWeight shuffles SRV records by weight using the algorithm
// described in RFC 2782.
func (addrs byPriorityWeight) shuffleByWeight() {
	sum := 0
	for _, addr := range addrs {
		sum += int(addr.Weight)
	}
	for sum > 0 && len(addrs) > 1 {
		s := 0
		n := rand.Intn(sum)
		for i := range addrs {
			s += int(addrs[i].Weight)
			if s > n {
				if i > 0 {
					addrs[0], addrs[i] = addrs[i], addrs[0]
				}
				break
			}
		}
		sum -= int(addrs[0].Weight)
		addrs = addrs[1:]
	}
}

// sort reorders SRV records as specified in RFC 2782.
func (addrs byPriorityWeight) sort() {
	slices.SortFunc(addrs, func(a, b *net.SRV) int {
		if r := cmp.Compare(a.Priority, b.Priority); r != 0 {
			return r
		}
		return cmp.Compare(a.Weight, b.Weight)
	})
	i := 0
	for j := 1; j < len(addrs); j++ {
		if addrs[i].Priority != addrs[j].Priority {
			addrs[i:j].shuffleByWeight()
			i = j
		}
	}
	addrs[i:].shuffleByWeight()
}

// byPref sorts MX records by preference
type byPref []*net.MX

// sort reorders MX records as specified in RFC 5321.
func (s byPref) sort() {
	for i := range s {
		j := rand.Intn(i + 1)
		s[i], s[j] = s[j], s[i]
	}
	slices.SortFunc(s, func(a, b *net.MX) int {
		return cmp.Compare(a.Pref, b.Pref)
	})
}

func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	if i := strings.LastIndexByte(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// ipVersion returns the provided network's IP version: '4', '6' or 0
// if network does not end in a '4' or '6' byte.
func ipVersion(network string) byte {
	if network == "" {
		return 0
	}
	n := network[len(network)-1]
	if n != '4' && n != '6' {
		n = 0
	}
	return n
}

type ipAttr struct {
	Scope      uint8
	Precedence uint8
	Label      uint8
}

const (
	scopeInterfaceLocal uint8 = 0x1
	scopeLinkLocal      uint8 = 0x2
	scopeAdminLocal     uint8 = 0x4
	scopeSiteLocal      uint8 = 0x5
	scopeOrgLocal       uint8 = 0x8
	scopeGlobal         uint8 = 0xe
)

func classifyScope(ip netip.Addr) uint8 {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return scopeLinkLocal
	}
	ipv6 := ip.Is6() && !ip.Is4In6()
	ipv6AsBytes := ip.As16()
	if ipv6 && ip.IsMulticast() {
		return ipv6AsBytes[1] & 0xf
	}
	// Site-local addresses are defined in RFC 3513 section 2.5.6
	// (and deprecated in RFC 3879).
	if ipv6 && ipv6AsBytes[0] == 0xfe && ipv6AsBytes[1]&0xc0 == 0xc0 {
		return scopeSiteLocal
	}
	return scopeGlobal
}

type policyTableEntry struct {
	Prefix     netip.Prefix
	Precedence uint8
	Label      uint8
}

type policyTable []policyTableEntry

// RFC 6724 section 2.1.
// Items are sorted by the size of their Prefix.Mask.Size,
var rfc6724policyTable = policyTable{
	{
		// "::1/128"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}), 128),
		Precedence: 50,
		Label:      0,
	},
	{
		// "::ffff:0:0/96"
		// IPv4-compatible, etc.
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}), 96),
		Precedence: 35,
		Label:      4,
	},
	{
		// "::/96"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 96),
		Precedence: 1,
		Label:      3,
	},
	{
		// "2001::/32"
		// Teredo
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01}), 32),
		Precedence: 5,
		Label:      5,
	},
	{
		// "2002::/16"
		// 6to4
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x02}), 16),
		Precedence: 30,
		Label:      2,
	},
	{
		// "3ffe::/16"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0x3f, 0xfe}), 16),
		Precedence: 1,
		Label:      12,
	},
	{
		// "fec0::/10"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfe, 0xc0}), 10),
		Precedence: 1,
		Label:      11,
	},
	{
		// "fc00::/7"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfc}), 7),
		Precedence: 3,
		Label:      13,
	},
	{
		// "::/0"
		Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0),
		Precedence: 40,
		Label:      1,
	},
}

// Classify returns the policyTableEntry of the entry with the longest
// matching prefix that contains ip.
// The table t must be sorted from largest mask size to smallest.
func (t policyTable) Classify(ip netip.Addr) policyTableEntry {
	// Prefix.Contains() will not match an IPv6 prefix for an IPv4 address.
	if ip.Is4() {
		ip = netip.AddrFrom16(ip.As16())
	}
	for _, ent := range t {
		if ent.Prefix.Contains(ip) {
			return ent
		}
	}
	return policyTableEntry{}
}

func ipAttrOf(ip netip.Addr) ipAttr {
	if !ip.IsValid() {
		return ipAttr{}
	}
	match := rfc6724policyTable.Classify(ip)
	return ipAttr{
		Scope:      classifyScope(ip),
		Precedence: match.Precedence,
		Label:      match.Label,
	}
}

// srcAddrs tries to UDP-connect to each address to see if it has a
// route. (This doesn't send any packets). The destination port
// number is irrelevant.
func srcAddrs(addrs []net.IPAddr) []netip.Addr {
	srcs := make([]netip.Addr, len(addrs))
	dst := net.UDPAddr{Port: 53}
	for i := range addrs {
		dst.IP = addrs[i].IP
		dst.Zone = addrs[i].Zone
		c, err := net.DialUDP("udp", nil, &dst)
		if err == nil {
			if src, ok := c.LocalAddr().(*net.UDPAddr); ok {
				srcs[i], _ = netip.AddrFromSlice(src.IP)
			}
			c.Close()
		}
	}
	return srcs
}

type byRFC6724Info struct {
	addr     net.IPAddr
	addrAttr ipAttr
	src      netip.Addr
	srcAttr  ipAttr
}

func sortByRFC6724(addrs []net.IPAddr) {
	if len(addrs) < 2 {
		return
	}
	sortByRFC6724withSrcs(addrs, srcAddrs(addrs))
}

// commonPrefixLen reports the length of the longest prefix (looking
// at the most significant, or leftmost, bits) that the
// two addresses have in common, up to the length of a's prefix (i.e.,
// the portion of the address not including the interface ID).
//
// If a or b is an IPv4 address as an IPv6 address, the IPv4 addresses
// are compared (with max common prefix length of 32).
// If a and b are different IP versions, 0 is returned.
//
// See https://tools.ietf.org/html/rfc6724#section-2.2
func commonPrefixLen(a netip.Addr, b net.IP) (cpl int) {
	if b4 := b.To4(); b4 != nil {
		b = b4
	}
	aAsSlice := a.AsSlice()
	if len(aAsSlice) != len(b) {
		return 0
	}
	// If IPv6, only up to the prefix (first 64 bits)
	if len(aAsSlice) > 8 {
		aAsSlice = aAsSlice[:8]
		b = b[:8]
	}
	for len(aAsSlice) > 0 {
		if aAsSlice[0] == b[0] {
			cpl += 8
			aAsSlice = aAsSlice[1:]
			b = b[1:]
			continue
		}
		bits := 8
		ab, bb := aAsSlice[0], b[0]
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}

// compareByRFC6724 compares two byRFC6724Info records and returns an integer
// indicating the order. It follows the algorithm and variable names from
// RFC 6724 section 6. Returns -1 if a is preferred, 1 if b is preferred,
// and 0 if they are equal.
func compareByRFC6724(a, b byRFC6724Info) int {
	DA := a.addr.IP
	DB := b.addr.IP
	SourceDA := a.src
	SourceDB := b.src
	attrDA := &a.addrAttr
	attrDB := &b.addrAttr
	attrSourceDA := &a.srcAttr
	attrSourceDB := &b.srcAttr

	const preferDA = -1
	const preferDB = 1

	// Rule 1: Avoid unusable destinations.
	// If DB is known to be unreachable or if Source(DB) is undefined, then
	// prefer DA.  Similarly, if DA is known to be unreachable or if
	// Source(DA) is undefined, then prefer DB.
	if !SourceDA.IsValid() && !SourceDB.IsValid() {
		return 0 // "equal"
	}
	if !SourceDB.IsValid() {
		return preferDA
	}
	if !SourceDA.IsValid() {
		return preferDB
	}

	// Rule 2: Prefer matching scope.
	// If Scope(DA) = Scope(Source(DA)) and Scope(DB) <> Scope(Source(DB)),
	// then prefer DA.  Similarly, if Scope(DA) <> Scope(Source(DA)) and
	// Scope(DB) = Scope(Source(DB)), then prefer DB.
	if attrDA.Scope == attrSourceDA.Scope && attrDB.Scope != attrSourceDB.Scope {
		return preferDA
	}
	if attrDA.Scope != attrSourceDA.Scope && attrDB.Scope == attrSourceDB.Scope {
		return preferDB
	}

	// Rule 3: Avoid deprecated addresses.
	// If Source(DA) is deprecated and Source(DB) is not, then prefer DB.
	// Similarly, if Source(DA) is not deprecated and Source(DB) is
	// deprecated, then prefer DA.

	// TODO(bradfitz): implement? low priority for now.

	// Rule 4: Prefer home addresses.
	// If Source(DA) is simultaneously a home address and care-of address
	// and Source(DB) is not, then prefer DA.  Similarly, if Source(DB) is
	// simultaneously a home address and care-of address and Source(DA) is
	// not, then prefer DB.

	// TODO(bradfitz): implement? low priority for now.

	// Rule 5: Prefer matching label.
	// If Label(Source(DA)) = Label(DA) and Label(Source(DB)) <> Label(DB),
	// then prefer DA.  Similarly, if Label(Source(DA)) <> Label(DA) and
	// Label(Source(DB)) = Label(DB), then prefer DB.
	if attrSourceDA.Label == attrDA.Label &&
		attrSourceDB.Label != attrDB.Label {
		return preferDA
	}
	if attrSourceDA.Label != attrDA.Label &&
		attrSourceDB.Label == attrDB.Label {
		return preferDB
	}

	// Rule 6: Prefer higher precedence.
	// If Precedence(DA) > Precedence(DB), then prefer DA.  Similarly, if
	// Precedence(DA) < Precedence(DB), then prefer DB.
	if attrDA.Precedence > attrDB.Precedence {
		return preferDA
	}
	if attrDA.Precedence < attrDB.Precedence {
		return preferDB
	}

	// Rule 7: Prefer native transport.
	// If DA is reached via an encapsulating transition mechanism (e.g.,
	// IPv6 in IPv4) and DB is not, then prefer DB.  Similarly, if DB is
	// reached via encapsulation and DA is not, then prefer DA.

	// TODO(bradfitz): implement? low priority for now.

	// Rule 8: Prefer smaller scope.
	// If Scope(DA) < Scope(DB), then prefer DA.  Similarly, if Scope(DA) >
	// Scope(DB), then prefer DB.
	if attrDA.Scope < attrDB.Scope {
		return preferDA
	}
	if attrDA.Scope > attrDB.Scope {
		return preferDB
	}

	// Rule 9: Use the longest matching prefix.
	// When DA and DB belong to the same address family (both are IPv6 or
	// both are IPv4 [but see below]): If CommonPrefixLen(Source(DA), DA) >
	// CommonPrefixLen(Source(DB), DB), then prefer DA.  Similarly, if
	// CommonPrefixLen(Source(DA), DA) < CommonPrefixLen(Source(DB), DB),
	// then prefer DB.
	//
	// However, applying this rule to IPv4 addresses causes
	// problems (see issues 13283 and 18518), so limit to IPv6.
	if DA.To4() == nil && DB.To4() == nil {
		commonA := commonPrefixLen(SourceDA, DA)
		commonB := commonPrefixLen(SourceDB, DB)

		if commonA > commonB {
			return preferDA
		}
		if commonA < commonB {
			return preferDB
		}
	}

	// Rule 10: Otherwise, leave the order unchanged.
	// If DA preceded DB in the original list, prefer DA.
	// Otherwise, prefer DB.
	return 0 // "equal"
}

func sortByRFC6724withSrcs(addrs []net.IPAddr, srcs []netip.Addr) {
	if len(addrs) != len(srcs) {
		panic("internal error")
	}
	addrInfos := make([]byRFC6724Info, len(addrs))
	for i, v := range addrs {
		addrAttrIP, _ := netip.AddrFromSlice(v.IP)
		addrInfos[i] = byRFC6724Info{
			addr:     addrs[i],
			addrAttr: ipAttrOf(addrAttrIP),
			src:      srcs[i],
			srcAttr:  ipAttrOf(srcs[i]),
		}
	}
	slices.SortStableFunc(addrInfos, compareByRFC6724)
	for i := range addrInfos {
		addrs[i] = addrInfos[i].addr
	}
}
