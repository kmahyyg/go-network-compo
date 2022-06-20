//go:build windows

package routes

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net/netip"
	"strconv"
	"unsafe"
)

// Types defined here does not need to judge 32bit or 64bit.
// Code from wireguard is licensed under MIT.
// Partially Grabbed from https://github.com/wireguard/wireguard-windows , tunnel/winipcfg/types.go

const (
	anySize = 1
)

var (
	AF_UNSPEC uint16 = 0
	AF_INET   uint16 = 2
	AF_INET6  uint16 = 23
)

// RouteProtocol enumeration type defines the routing mechanism that an IP route was added with, as described in RFC 4292.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_route_protocol
type RouteProtocol uint32

const (
	RouteProtocolOther RouteProtocol = iota + 1
	RouteProtocolLocal
	RouteProtocolNetMgmt
	RouteProtocolIcmp
	RouteProtocolEgp
	RouteProtocolGgp
	RouteProtocolHello
	RouteProtocolRip
	RouteProtocolIsIs
	RouteProtocolEsIs
	RouteProtocolCisco
	RouteProtocolBbn
	RouteProtocolOspf
	RouteProtocolBgp
	RouteProtocolIdpr
	RouteProtocolEigrp
	RouteProtocolDvmrp
	RouteProtocolRpl
	RouteProtocolDHCP
	RouteProtocolNTAutostatic   = 10002
	RouteProtocolNTStatic       = 10006
	RouteProtocolNTStaticNonDOD = 10007
)

// RouteOrigin enumeration type defines the origin of the IP route.
// https://docs.microsoft.com/en-us/windows/desktop/api/nldef/ne-nldef-nl_route_origin
type RouteOrigin uint32

const (
	RouteOriginManual RouteOrigin = iota
	RouteOriginWellKnown
	RouteOriginDHCP
	RouteOriginRouterAdvertisement
	RouteOrigin6to4
)

type AddressFamily uint16

// RawSockaddrInet union contains an IPv4, an IPv6 address, or an address family.
// https://docs.microsoft.com/en-us/windows/desktop/api/ws2ipdef/ns-ws2ipdef-_sockaddr_inet
type RawSockaddrInet struct {
	Family AddressFamily
	data   [26]byte
}

func ntohs(i uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&i))[:])
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// AddrPort returns the IP address and port.
func (addr *RawSockaddrInet) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr(), addr.Port())
}

// Addr returns IPv4 or IPv6 address, or an invalid address if the address is neither.
func (addr *RawSockaddrInet) Addr() netip.Addr {
	switch addr.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Addr)
	case windows.AF_INET6:
		raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		a := netip.AddrFrom16(raw.Addr)
		if raw.Scope_id != 0 {
			a = a.WithZone(strconv.FormatUint(uint64(raw.Scope_id), 10))
		}
		return a
	}
	return netip.Addr{}
}

// Port returns the port if the address if IPv4 or IPv6, or 0 if neither.
func (addr *RawSockaddrInet) Port() uint16 {
	switch addr.Family {
	case windows.AF_INET:
		return ntohs((*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Port)
	case windows.AF_INET6:
		return ntohs((*windows.RawSockaddrInet6)(unsafe.Pointer(addr)).Port)
	}
	return 0
}

// IPAddressPrefix structure stores an IP address prefix.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_ip_address_prefix
type IPAddressPrefix struct {
	RawPrefix    RawSockaddrInet
	PrefixLength uint8
	_            [2]byte
}

// Prefix returns IP address prefix as netip.Prefix.
func (prefix *IPAddressPrefix) Prefix() netip.Prefix {
	switch prefix.RawPrefix.Family {
	case windows.AF_INET:
		return netip.PrefixFrom(netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	case windows.AF_INET6:
		return netip.PrefixFrom(netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&prefix.RawPrefix)).Addr), int(prefix.PrefixLength))
	}
	return netip.Prefix{}
}

// LUID represents a network interface.
type LUID uint64

// MibIPforwardRow2 structure stores information about an IP route entry.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_row2
type MibIPforwardRow2 struct {
	InterfaceLUID        LUID
	InterfaceIndex       uint32
	DestinationPrefix    IPAddressPrefix
	NextHop              RawSockaddrInet
	SitePrefixLength     uint8
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             RouteProtocol
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               RouteOrigin
}

func Retrieve() ([]NetRoute, error) {

}
