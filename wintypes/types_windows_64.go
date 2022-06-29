//go:build windows && (amd64 || arm64)

package wintypes

import "golang.org/x/sys/windows"

// Types defined here ONLY works for 64-bit.
// Code from wireguard is licensed under MIT.
// Totally Grabbed from https://github.com/wireguard/wireguard-windows , tunnel/winipcfg/types.go

// mibIPforwardTable2 structure contains a table of IP route entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_table2
type mibIPforwardTable2 struct {
	numEntries uint32
	table      [anySize]MibIPforwardRow2
}

// MibIfRow2 structure stores information about a particular interface.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_if_row2
type MibIfRow2 struct {
	InterfaceLUID               LUID
	InterfaceIndex              uint32
	InterfaceGUID               windows.GUID
	alias                       [ifMaxStringSize + 1]uint16
	description                 [ifMaxStringSize + 1]uint16
	physicalAddressLength       uint32
	physicalAddress             [ifMaxPhysAddressLength]byte
	permanentPhysicalAddress    [ifMaxPhysAddressLength]byte
	MTU                         uint32
	Type                        IfType
	TunnelType                  TunnelType
	MediaType                   NdisMedium
	PhysicalMediumType          NdisPhysicalMedium
	AccessType                  NetIfAccessType
	DirectionType               NetIfDirectionType
	InterfaceAndOperStatusFlags InterfaceAndOperStatusFlags
	OperStatus                  IfOperStatus
	AdminStatus                 NetIfAdminStatus
	MediaConnectState           NetIfMediaConnectState
	NetworkGUID                 windows.GUID
	ConnectionType              NetIfConnectionType
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}
