// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package resolver

import (
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/moriyoshi/badass-mail-redirector/internal/resolver/internal"
)

type WindowsConfLoader struct {
	sync.Mutex
	proto       DNSConfig        // read-only copy of the config
	nowGetter   func() time.Time // returns current time
	logger      func(string, ...interface{})
	cacheMaxAge time.Duration
	noReload    bool // set to true to disable checks for updates to resolv.conf
	expiry      time.Time
	dnsConfig   *DNSConfig // parsed resolv.conf structure used in lookups
}

func (loader *WindowsConfLoader) log(msg string, args ...interface{}) {
	if loader.logger != nil {
		loader.logger(msg, args...)
	}
}

func (loader *WindowsConfLoader) Prototype() DNSConfig {
	return loader.proto
}

func (loader *WindowsConfLoader) Get(context.Context) (*DNSConfig, error) {
	loader.Lock()
	defer loader.Unlock()

	conf := loader.dnsConfig
	now := loader.nowGetter()

	if conf != nil && loader.noReload || now.Before(loader.expiry) {
		return conf, nil
	}

	newConf, err := loader.load()
	if err != nil {
		if conf != nil {
			return conf, nil
		}
		return nil, err
	}

	loader.expiry = now.Add(loader.cacheMaxAge)
	loader.dnsConfig = newConf
	return newConf, nil
}

func (loader *WindowsConfLoader) load() (conf *DNSConfig, err error) {
	loader.log("fetching network configuration")
	aas, err := adapterAddresses()
	if err != nil {
		return
	}

	var servers []string
	for _, aa := range aas {
		// Only take interfaces whose OperStatus is IfOperStatusUp(0x01) into DNS configs.
		if aa.OperStatus != internal.IfOperStatusUp {
			continue
		}

		// Only take interfaces which have at least one gateway
		if aa.FirstGatewayAddress == nil {
			continue
		}

		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			sa, err := dns.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			var ip net.IP
			switch sa := sa.(type) {
			case *syscall.SockaddrInet4:
				ip = net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3])
				loader.log("found IPv4 DNS server %s", ip)
			case *syscall.SockaddrInet6:
				ip = make(net.IP, net.IPv6len)
				copy(ip, sa.Addr[:])
				loader.log("found IPv6 DNS server %s", ip)
				if ip[0] == 0xfe && ip[1] == 0xc0 {
					// fec0/10 IPv6 addresses are site local anycast DNS
					// addresses Microsoft sets by default if no other
					// IPv6 DNS address is set. Site local anycast is
					// deprecated since 2004, see
					// https://datatracker.ietf.org/doc/html/rfc3879
					continue
				}
			default:
				// Unexpected type.
				continue
			}
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}

	conf = new(DNSConfig)
	*conf = loader.proto
	conf.Servers = servers
	return
}

// adapterAddresses returns a list of IP adapter and address
// structures. The structure contains an IP adapter and flattened
// multiple IP addresses including unicast, anycast and multicast
// addresses.
func adapterAddresses() ([]*internal.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		const flags = internal.GAA_FLAG_INCLUDE_PREFIX | internal.GAA_FLAG_INCLUDE_GATEWAYS
		err := internal.GetAdaptersAddresses(syscall.AF_UNSPEC, flags, 0, (*internal.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err.(syscall.Errno) != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
		if l <= uint32(len(b)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
	var aas []*internal.IpAdapterAddresses
	for aa := (*internal.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}

func NewWindowsConfLoader(options ...ResolverOptionFunc) (*WindowsConfLoader, error) {
	loader := &WindowsConfLoader{
		proto:       dnsConfigProtoDefault,
		nowGetter:   time.Now,
		cacheMaxAge: 10 * time.Second,
		noReload:    false,
	}
	for _, fn := range options {
		err := fn(loader)
		if err != nil {
			return nil, err
		}
	}
	return loader, nil
}

func init() {
	OptionFuncHooks.CacheMaxAge = OptionFuncHooks.CacheMaxAge.Add(func(loader any, value time.Duration) (bool, error) {
		if loader, ok := (loader).(*WindowsConfLoader); ok {
			loader.cacheMaxAge = value
			return true, nil
		}
		return false, nil
	})
	OptionFuncHooks.NowGetter = OptionFuncHooks.NowGetter.Add(func(loader any, value func() time.Time) (bool, error) {
		if loader, ok := (loader).(*WindowsConfLoader); ok {
			loader.nowGetter = value
			return true, nil
		}
		return false, nil
	})
	OptionFuncHooks.DiagosticLogger.Add(func(loader any, logger func(string, ...interface{})) (bool, error) {
		if loader, ok := (loader).(*WindowsConfLoader); ok {
			loader.logger = logger
			return true, nil
		}
		return false, nil
	})
	OptionFuncHooks.NoReload = OptionFuncHooks.NoReload.Add(func(loader any, value bool) (bool, error) {
		if loader, ok := (loader).(*WindowsConfLoader); ok {
			loader.noReload = value
			return true, nil
		}
		return false, nil
	})
	loader, err := NewWindowsConfLoader()
	if err != nil {
		panic(err)
	}
	defaultConfigLoader = loader.Get
}
