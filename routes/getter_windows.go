//go:build windows

package routes

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	AF_UNSPEC = 0
	AF_INET   = 2
	AF_INET6  = 23
)

type IP_ADDRESS_PREFIX struct {
	Prefix       *windows.RawSockaddrAny
	PrefixLength byte
}

var NL_ROUTE_PROTOCOL = map[uint32]string{
	uint32(1):  "RouteProtocolOther",
	uint32(2):  "RouteProtocolLocal",
	uint32(3):  "RouteProtocolNetMgmt",
	uint32(4):  "RouteProtocolIcmp",
	uint32(5):  "RouteProtocolEgp",
	uint32(6):  "RouteProtocolGgp",
	uint32(7):  "RouteProtocolHello",
	uint32(8):  "RouteProtocolRip",
	uint32(9):  "RouteProtocolIsIs",
	uint32(10): "RouteProtocolEsIs",
	uint32(11): "RouteProtocolCisco",
	uint32(12): "RouteProtocolBbn",
	uint32(13): "RouteProtocolOspf",
	uint32(14): "RouteProtocolBgp",
	uint32(15): "RouteProtocolIdpr",
	uint32(16): "RouteProtocolEigrp",
	uint32(17): "RouteProtocolDvmrp",
	uint32(18): "RouteProtocolRpl",
	uint32(19): "RouteProtocolDhcp",
}

var NL_ROUTE_ORIGIN = map[uint32]string{
	uint32(0): "NlroManual",
	uint32(1): "NlroWellKnown",
	uint32(2): "NlroDHCP",
	uint32(3): "NlroRouterAdvertisement",
	uint32(4): "Nlro6to4",
}

type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    IP_ADDRESS_PREFIX
	NextHop              windows.RawSockaddrAny
	SitePrefixLength     byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             bool
	AutoconfigureAddress bool
	Publish              bool
	Immortal             bool
	Age                  uint32
	Origin               byte
}

type win_MIB_IPFORWARD_TABLE2 struct {
	NumEntries uint32
	Table      []MIB_IPFORWARD_ROW2
}

func Retrieve() ([]NetRoute, error) {

}

func getIPForwardTable2(addr_famliy uint8) (any, error) {
	for {
		bufSize := 4096
		bufFact := 1
		buf := make([]byte, bufSize*bufFact)
		optTable := &buf[0]
		iphlpDLL, err := syscall.LoadLibrary("IPHLPAPI.dll")
		if err != nil {
			return nil, err
		}
		procGetIPForwardTable2, err := syscall.GetProcAddress(iphlpDLL, "GetIpForwardTable2")
		if err != nil {
			return nil, err
		}
		ret, _, errno := syscall.SyscallN(procGetIPForwardTable2, uintptr(addr_famliy), uintptr(unsafe.Pointer(optTable)))
		if ret != 0 {
			if syscall.Errno(ret) == syscall.ERROR_INSUFFICIENT_BUFFER {
				bufFact++
				buf = make([]byte, bufSize*bufFact)
				continue
			}
			return nil, errno
		}
		return optTable, nil
	}
}
