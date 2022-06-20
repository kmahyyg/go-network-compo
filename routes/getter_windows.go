//go:build windows

package routes

import (
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	AF_UNSPEC              uint16 = 0
	AF_INET                uint16 = 2
	AF_INET6               uint16 = 23
	iphlpDLL                      = syscall.NewLazyDLL("IPHLPAPI.dll")
	procGetIPForwardTable2        = iphlpDLL.NewProc("GetIpForwardTable2")
)

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

type IP_ADDRESS_PREFIX struct {
	Prefix       *windows.RawSockaddrAny // sockaddr_inet
	PrefixLength byte                    // uint8
}

type _NL_ROUTE_ORIGIN = uint32
type _NL_ROUTE_PROTOCOL = uint32

type _NET_LUID struct {
	// equals to NET_LUID_LH
	Value uint64 // length 8
	// [0:24] Reserved, [24:48] NetLuidIndex, [48:64] IfType
}

// length 104
type MIB_IPFORWARD_ROW2 struct {
	InterfaceLuid        _NET_LUID // length 8
	InterfaceIndex       uint32    // ulong
	DestinationPrefix    IP_ADDRESS_PREFIX
	NextHop              windows.RawSockaddrAny // sockaddr_inet
	SitePrefixLength     byte                   // unsigned char, uint8
	ValidLifetime        uint32                 // ulong
	PreferredLifetime    uint32                 // ulong
	Metric               uint32                 // ulong
	Protocol             _NL_ROUTE_PROTOCOL     // enum
	Loopback             byte                   // bool, uint8
	AutoconfigureAddress byte                   // bool, uint8
	Publish              byte                   // bool, uint8
	Immortal             byte                   // bool, uint8
	Age                  uint32                 // ulong
	Origin               _NL_ROUTE_ORIGIN       // enum
}

type MIB_IPFORWARD_TABLE2 struct {
	NumEntries uint32
	Table      [1]MIB_IPFORWARD_ROW2
}

func Retrieve() ([]NetRoute, error) {
	optTable, err := getIPForwardTable2(AF_INET)
	if err != nil {
		return nil, err
	}
	tablePtr := (*MIB_IPFORWARD_TABLE2)(unsafe.Pointer(&optTable[0]))
	rowsInTable := make([]MIB_IPFORWARD_ROW2, int(tablePtr.NumEntries))
	for i := 0; i < int(tablePtr.NumEntries); i++ {
		rowsInTable[i] = *(*MIB_IPFORWARD_ROW2)(unsafe.Pointer(uintptr(unsafe.Pointer(&tablePtr.Table[0])) + uintptr(i)*unsafe.Sizeof(tablePtr.Table[0])))
	}
	return nil, nil
}

func getIPForwardTable2(addr_famliy uint16) ([]byte, error) {
	if addr_famliy != AF_INET && addr_famliy != AF_INET6 && addr_famliy != AF_UNSPEC {
		return nil, errors.New("unknown address family.")
	}
	bufSize := 8192
	bufFact := 1
	for {
		buf := make([]byte, bufSize*bufFact)
		optTable := &buf[0]
		ret, _, errno := procGetIPForwardTable2.Call(uintptr(addr_famliy), uintptr(unsafe.Pointer(optTable)))
		if ret != 0 {
			if syscall.Errno(ret) == syscall.ERROR_INSUFFICIENT_BUFFER {
				bufFact++
				buf = make([]byte, bufSize*bufFact)
				continue
			}
			return nil, errno
		}
		return buf, nil
	}
}
