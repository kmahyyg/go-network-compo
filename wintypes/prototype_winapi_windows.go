//go:build windows

package wintypes

import (
	"github.com/kmahyyg/go-network-compo/utils"
	"golang.org/x/sys/windows"
	"net"
	"unsafe"
)

// Code from wireguard is licensed under MIT.
// Totally Grabbed from https://github.com/wireguard/wireguard-windows , tunnel/winipcfg/winipcfg.go

//sys	freeMibTable(memory unsafe.Pointer) = iphlpapi.FreeMibTable
//sys   freeInterfaceDnsSettings(memory unsafe.Pointer) = iphlpapi.FreeInterfaceDnsSettings
//sys	getIfEntry2(row *MibIfRow2) (ret error) = iphlpapi.GetIfEntry2
//sys   getIfTable2(table **MibIfTable2) (ret error) = iphlpapi.GetIfTable2
//sys   getInterfaceDnsSettings(iface *windows.GUID, settings *DnsInterfaceSettings) (ret error) = iphlpapi.GetInterfaceDnsSettings
//sys	initializeIPForwardEntry(route *MibIPforwardRow2) = iphlpapi.InitializeIpForwardEntry
//sys	getIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.GetIpForwardEntry2
//sys	setIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.SetIpForwardEntry2
//sys	createIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.CreateIpForwardEntry2
//sys	deleteIPForwardEntry2(route *MibIPforwardRow2) (ret error) = iphlpapi.DeleteIpForwardEntry2
//sys	getIPForwardTable2(family AddressFamily, table **mibIPforwardTable2) (ret error) = iphlpapi.GetIpForwardTable2
//sys   dnsQueryConfig(config DnsConfigType, flag uint32, wsAdapterName uintptr, reserved uintptr, buffer *byte, buflen *uint32) (ret error) = dnsapi.DnsQueryConfig

// GetIPForwardTable2 function retrieves the IP route entries on the local computer.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardtable2
func GetIPForwardTable2(family AddressFamily) ([]MibIPforwardRow2, error) {
	var tab *mibIPforwardTable2
	err := getIPForwardTable2(family, &tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIPforwardRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

// GetIfTable2 function retrieves the MIB-II interface table.
// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2
func GetIfTable2() ([]MibIfRow2, error) {
	var tab *MibIfTable2
	err := getIfTable2(&tab)
	if err != nil {
		return nil, err
	}
	t := append(make([]MibIfRow2, 0, tab.numEntries), tab.get()...)
	tab.free()
	return t, nil
}

// GetInterfaceDnsSettings Retrieves the DNS settings from the interface specified in the Interface parameter.
// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings
func GetInterfaceDnsSettings(iface *windows.GUID, settings *DnsInterfaceSettings) (ret error) {
	settings.Version = DnsInterfaceSettingsVersion1
	err := getInterfaceDnsSettings(iface, settings)
	if err != nil {
		return err
	}
	return nil
}

// DnsQueryConfig enables application programmers to query for the configuration of the local
// computer or a specific adapter.
// https://docs.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryconfig
// GetDNSServerList is hardcoded here, bufLen is used for retrying when met ERROR_MORE_DATA.
func DnsQueryConfig_DNSServerList() (data []net.IP, ret error) {
	bufLen := 64
	ip4Arr := make([]byte, bufLen)
	bufLenDWORD := uint32(bufLen)
	err := dnsQueryConfig(DnsConfigDnsServerList, 0, 0, 0, &ip4Arr[0], &bufLenDWORD)
	if err != nil {
		return nil, err
	}
	// return buf as IP4_ARRAY
	// https://docs.microsoft.com/en-us/windows/win32/api/windns/ns-windns-ip4_array
	// similar procedure as anySize Array
	// https://cs.github.com/namealt/winsdk10/blob/d1acc505c51b11a6ceafb0f93c9dc584b8b4a9d3/Include/10.0.14393.0/um/WinDNS.h#L70
	ip4a := (*Ip4Array)(unsafe.Pointer(&ip4Arr[0]))
	t := append(make([]Ip4Address, 0, ip4a.AddrCount), ip4a.get()...)
	data = make([]net.IP, ip4a.AddrCount)
	for i, v := range t {
		data[i] = utils.Uint32ToNetIP_LittleEndian(v)
	}
	return data, nil
}
