//go:build windows

package internal

import (
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

type SocketAddress struct {
	Sockaddr       *syscall.RawSockaddrAny
	SockaddrLength int32
}

type IpAdapterUnicastAddress struct {
	Length             uint32
	Flags              uint32
	Next               *IpAdapterUnicastAddress
	Address            SocketAddress
	PrefixOrigin       int32
	SuffixOrigin       int32
	DadState           int32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

type IpAdapterGatewayAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterGatewayAddress
	Address  SocketAddress
}

type IpAdapterMulticastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterMulticastAddress
	Address SocketAddress
}

type IpAdapterPrefix struct {
	Length       uint32
	Flags        uint32
	Next         *IpAdapterPrefix
	Address      SocketAddress
	PrefixLength uint32
}

type IpAdapterAnycastAddress struct {
	Length  uint32
	Flags   uint32
	Next    *IpAdapterAnycastAddress
	Address SocketAddress
}

type IpAdapterDnsServerAdapter struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterDnsServerAdapter
	Address  SocketAddress
}

type IpAdapterWinsServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IpAdapterWinsServerAddress
	Address  SocketAddress
}

type IpAdapterAddresses struct {
	Length                 uint32
	IfIndex                uint32
	Next                   *IpAdapterAddresses
	AdapterName            *byte
	FirstUnicastAddress    *IpAdapterUnicastAddress
	FirstAnycastAddress    *IpAdapterAnycastAddress
	FirstMulticastAddress  *IpAdapterMulticastAddress
	FirstDnsServerAddress  *IpAdapterDnsServerAdapter
	DnsSuffix              *uint16
	Description            *uint16
	FriendlyName           *uint16
	PhysicalAddress        [syscall.MAX_ADAPTER_ADDRESS_LENGTH]byte
	PhysicalAddressLength  uint32
	Flags                  uint32
	Mtu                    uint32
	IfType                 uint32
	OperStatus             uint32
	Ipv6IfIndex            uint32
	ZoneIndices            [16]uint32
	FirstPrefix            *IpAdapterPrefix
	TransmitLinkSpeed      uint64
	ReceiveLinkSpeed       uint64
	FirstWinsServerAddress *IpAdapterWinsServerAddress
	FirstGatewayAddress    *IpAdapterGatewayAddress
}

const (
	IfOperStatusUp             = 1
	IfOperStatusDown           = 2
	IfOperStatusTesting        = 3
	IfOperStatusUnknown        = 4
	IfOperStatusDormant        = 5
	IfOperStatusNotPresent     = 6
	IfOperStatusLowerLayerDown = 7
)

const (
	GAA_FLAG_INCLUDE_PREFIX   = 0x00000010
	GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
)

var (
	procGetAdaptersAddresses = modiphlpapi.NewProc("GetAdaptersAddresses")
	procGetSystemDirectoryW  = kernel32.NewProc("GetSystemDirectoryW")
)

func GetAdaptersAddresses(family uint32, flags uint32, reserved uintptr, adapterAddresses *IpAdapterAddresses, sizePointer *uint32) (errcode error) {
	r0, _, _ := syscall.SyscallN(procGetAdaptersAddresses.Addr(), 5, uintptr(family), uintptr(flags), uintptr(reserved), uintptr(unsafe.Pointer(adapterAddresses)), uintptr(unsafe.Pointer(sizePointer)), 0)
	if r0 != 0 {
		errcode = syscall.Errno(r0)
	}
	return
}

const _MAX_PATH = 260 // https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation

var sysDirectory string

func init() {
	var path [_MAX_PATH + 1]uint16

	l, _, _ := syscall.SyscallN(procGetSystemDirectoryW.Addr(), uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)-1))
	if l == 0 || l > uintptr(len(path)-1) {
		panic("Unable to determine system directory")
	}
	s := make([]byte, 0, _MAX_PATH)
	for i := uintptr(0); i < l; {
		if utf16.IsSurrogate(rune(path[i])) {
			if i+1 < l {
				s = utf8.AppendRune(s, utf16.DecodeRune(rune(path[i]), rune(path[i+1])))
				i += 2
			} else {
				panic("invalid UTF-16 sequence")
			}
		} else {
			s = utf8.AppendRune(s, rune(path[i]))
			i++
		}
	}
	sysDirectory = string(s)
}

func GetSystemDirectory() string {
	return sysDirectory
}
