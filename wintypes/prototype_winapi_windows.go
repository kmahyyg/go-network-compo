//go:build windows

package wintypes

import (
	"golang.org/x/sys/windows"
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
