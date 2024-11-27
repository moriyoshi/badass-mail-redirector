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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Resolver looks up names and IP addresses.
type Resolver struct {
	net.Resolver
	hostLookupOrder HostLookupOrder
	nowGetter       func() time.Time // for testing
	configGetter    func(context.Context) (*DNSConfig, error)
	uplooker        Uplooker
	avoidEDNS0      bool // avoid using EDNS0 extension
	soffset         uint32
	wg              sync.WaitGroup
	lookupGroup     singleflight.Group
}

type Uplooker interface {
	LookupHost(context.Context, string) ([]string, string)
	LookupAddr(context.Context, string) []string
}

// HostLookupOrder specifies the order of LookupHost lookup strategies.
// It is basically a simplified representation of nsswitch.conf.
// "files" means /etc/hosts.
type HostLookupOrder int

const (
	// hostLookupCgo means defer to cgo.
	HostLookupNone     HostLookupOrder = iota
	HostLookupFilesDNS                 // files first
	HostLookupDNSFiles                 // dns first
	HostLookupFiles                    // only files
	HostLookupDNS                      // only DNS
)

var lookupOrderName = map[HostLookupOrder]string{
	HostLookupNone:     "(none)",
	HostLookupFilesDNS: "files,dns",
	HostLookupDNSFiles: "dns,files",
	HostLookupFiles:    "files",
	HostLookupDNS:      "dns",
}

func (o HostLookupOrder) String() string {
	if s, ok := lookupOrderName[o]; ok {
		return s
	}
	return "HostLookupOrder=" + strconv.Itoa(int(o)) + "??"
}

type dnsConfigKey struct{}

type hostLookupOrderKey struct{}

var DNSConfigKey dnsConfigKey
var HostLookupOrderKey hostLookupOrderKey

func (r *Resolver) getConfAndOrder(ctx context.Context) (conf *DNSConfig, order HostLookupOrder, err error) {
	{
		v := ctx.Value(DNSConfigKey)
		if v != nil {
			conf = v.(*DNSConfig)
		}
	}
	{
		v := ctx.Value(HostLookupOrderKey)
		if v != nil {
			order = v.(HostLookupOrder)
		}
	}
	if conf == nil {
		conf, err = r.configGetter(ctx)
		if err != nil {
			return
		}
	}
	if order == HostLookupNone {
		order = r.hostLookupOrder
		if r.uplooker == nil && order == HostLookupFiles {
			err = errors.New("order is set to HostLookupFiles, but no uplooker is set for Resolver")
		}
	}
	return
}

// LookupHost looks up the given host using the local resolver.
// It returns a slice of that host's addresses.
func (r *Resolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	// Make sure that no matter what we do later, host=="" is rejected.
	if host == "" {
		return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, nil
	}
	conf, order, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host}
	}
	return r.goLookupHostOrder(ctx, conf, host, order)
}

// LookupIP looks up host for the given network using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil, net.UnknownNetworkError(network)
	}

	if host == "" {
		return nil, &net.DNSError{Err: ErrNoSuchHost.Error(), Name: host}
	}

	conf, order, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: host}
	}
	addrs, err := r.internetAddrList(ctx, conf, network, host, order)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.(*net.IPAddr).IP)
	}
	return ips, nil
}

// LookupNetIP looks up host using the local resolver.
// It returns a slice of that host's IP addresses of the type specified by
// network.
// The network must be one of "ip", "ip4" or "ip6".
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	// TODO(bradfitz): make this efficient, making the internal net package
	// type throughout be netip.Addr and only converting to the net.IP slice
	// version at the edge. But for now (2021-10-20), this is a wrapper around
	// the old way.
	ips, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	ret := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ret = append(ret, a)
		}
	}
	return ret, nil
}

// LookupCNAME returns the canonical name for the given host.
// Callers that do not care about the canonical name can call
// [LookupHost] or [LookupIP] directly; both take care of resolving
// the canonical name as part of the lookup.
//
// A canonical name is the final name after following zero
// or more CNAME records.
// LookupCNAME does not return an error if host does not
// contain DNS "CNAME" records, as long as host resolves to
// address records.
//
// The returned canonical name is validated to be a properly
// formatted presentation-format domain name.
func (r *Resolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	conf, order, err := r.getConfAndOrder(ctx)
	if err != nil {
		return "", &net.DNSError{Err: err.Error(), Name: host}
	}
	cname, err := r.goLookupCNAMEOrder(ctx, conf, host, order)
	if err != nil {
		return "", err
	}
	if !isDomainName(cname) {
		return "", &net.DNSError{Err: ErrMalformedDNSRecordsDetail.Error(), Name: host}
	}
	return cname, nil
}

// LookupSRV tries to resolve an [SRV] query of the given service,
// protocol, and domain name. The proto is "tcp" or "udp".
// The returned records are sorted by priority and randomized
// by weight within a priority.
//
// LookupSRV constructs the DNS name to look up following RFC 2782.
// That is, it looks up _service._proto.name. To accommodate services
// publishing SRV records under non-standard names, if both service
// and proto are empty strings, LookupSRV looks up name directly.
//
// The returned service names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	conf, _, err := r.getConfAndOrder(ctx)
	if err != nil {
		return "", nil, &net.DNSError{Err: err.Error(), Name: name}
	}
	cname, addrs, err := r.goLookupSRV(ctx, conf, service, proto, name)
	if err != nil {
		return "", nil, err
	}
	if cname != "" && !isDomainName(cname) {
		return "", nil, &net.DNSError{Err: "SRV header name is invalid", Name: name}
	}
	filteredAddrs := make([]*net.SRV, 0, len(addrs))
	for _, addr := range addrs {
		if addr == nil {
			continue
		}
		if !isDomainName(addr.Target) {
			continue
		}
		filteredAddrs = append(filteredAddrs, addr)
	}
	if len(addrs) != len(filteredAddrs) {
		return cname, filteredAddrs, &net.DNSError{Err: ErrMalformedDNSRecordsDetail.Error(), Name: name}
	}
	return cname, filteredAddrs, nil
}

// LookupMX returns the DNS MX records for the given domain name sorted by preference.
//
// The returned mail server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	conf, _, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: name}
	}
	records, err := r.goLookupMX(ctx, conf, name)
	if err != nil {
		return nil, err
	}
	filteredMX := make([]*net.MX, 0, len(records))
	for _, mx := range records {
		if mx == nil {
			continue
		}
		if !isDomainName(mx.Host) {
			continue
		}
		filteredMX = append(filteredMX, mx)
	}
	if len(records) != len(filteredMX) {
		return filteredMX, &net.DNSError{Err: ErrMalformedDNSRecordsDetail.Error(), Name: name}
	}
	return filteredMX, nil
}

// LookupNS returns the DNS NS records for the given domain name.
//
// The returned name server names are validated to be properly
// formatted presentation-format domain names. If the response contains
// invalid names, those records are filtered out and an error
// will be returned alongside the remaining results, if any.
func (r *Resolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	conf, _, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: name}
	}
	records, err := r.goLookupNS(ctx, conf, name)
	if err != nil {
		return nil, err
	}
	filteredNS := make([]*net.NS, 0, len(records))
	for _, ns := range records {
		if ns == nil {
			continue
		}
		if !isDomainName(ns.Host) {
			continue
		}
		filteredNS = append(filteredNS, ns)
	}
	if len(records) != len(filteredNS) {
		return filteredNS, &net.DNSError{Err: ErrMalformedDNSRecordsDetail.Error(), Name: name}
	}
	return filteredNS, nil
}

// LookupTXT returns the DNS TXT records for the given domain name.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	conf, _, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: name}
	}
	return r.goLookupTXT(ctx, conf, name)
}

// LookupAddr performs a reverse lookup for the given address, returning a list
// of names mapping to that address.
//
// The returned names are validated to be properly formatted presentation-format
// domain names. If the response contains invalid names, those records are filtered
// out and an error will be returned alongside the remaining results, if any.
func (r *Resolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	conf, order, err := r.getConfAndOrder(ctx)
	if err != nil {
		return nil, &net.DNSError{Err: err.Error(), Name: addr}
	}
	names, err := r.goLookupPTROrder(ctx, conf, addr, order)
	if err != nil {
		return nil, err
	}
	filteredNames := make([]string, 0, len(names))
	for _, name := range names {
		if isDomainName(name) {
			filteredNames = append(filteredNames, name)
		}
	}
	if len(names) != len(filteredNames) {
		return filteredNames, &net.DNSError{Err: ErrMalformedDNSRecordsDetail.Error(), Name: addr}
	}
	return filteredNames, nil
}

func WithHostLookupOrder(order HostLookupOrder) ResolverOptionFunc {
	return func(r any) error {
		if resolver, ok := r.(*Resolver); ok {
			if resolver.uplooker == nil {
				switch order {
				case HostLookupFiles, HostLookupFilesDNS, HostLookupDNSFiles:
					return fmt.Errorf("order is set to %s, but no uplooker is set for Resolver", order)
				}
			}
			resolver.hostLookupOrder = order
			return nil
		}
		return errors.New("option not applicable to Resolver")
	}
}

func WithConfigGetter(fn func(context.Context) (*DNSConfig, error)) ResolverOptionFunc {
	return func(r any) error {
		if resolver, ok := r.(*Resolver); ok {
			resolver.configGetter = fn
			return nil
		}
		return errors.New("option not applicable to Resolver")
	}
}

func WithStaticDNSConfig(conf *DNSConfig) ResolverOptionFunc {
	return func(r any) error {
		if resolver, ok := r.(*Resolver); ok {
			resolver.configGetter = func(context.Context) (*DNSConfig, error) {
				return conf, nil
			}
			return nil
		}
		return errors.New("option not applicable to Resolver")
	}
}

func WithUplooker(uplooker Uplooker) ResolverOptionFunc {
	return func(r any) error {
		if resolver, ok := r.(*Resolver); ok {
			resolver.uplooker = uplooker
			return nil
		}
		return errors.New("option not applicable to Resolver")
	}
}

func WithAvoidEDNS0(avoid bool) ResolverOptionFunc {
	return func(r any) error {
		if resolver, ok := r.(*Resolver); ok {
			resolver.avoidEDNS0 = avoid
			return nil
		}
		return errors.New("option not applicable to Resolver")
	}
}

func NewResolver(options ...ResolverOptionFunc) (*Resolver, error) {
	r := &Resolver{
		hostLookupOrder: HostLookupDNS,
		nowGetter:       time.Now,
		configGetter:    GetSystemDNSConfig,
	}
	for _, fn := range options {
		if err := fn(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

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
