//go:build windows

package dns

import (
	"github.com/kmahyyg/go-network-compo/wintypes"
	"golang.org/x/sys/windows"
)

func Retrieve(manualSets bool) (map[string]string, error) {
	ifaceDNSmap := make(map[string]string, 0)
	if manualSets { // Fetch all Interfaces
		ifaces, err := wintypes.GetIfTable2()
		if err != nil {
			return nil, err
		}
		for _, sIf := range ifaces {
			if sIf.OperStatus != wintypes.IfOperStatusUp {
				continue
			}
			func() {
				dnsIfSetting := &wintypes.DnsInterfaceSettings{Version: wintypes.DnsInterfaceSettingsVersion1}
				defer dnsIfSetting.Free()
				err = wintypes.GetInterfaceDnsSettings(&sIf.InterfaceGUID, dnsIfSetting)
				if err != nil {
					return
				}
				if dnsIfSetting.NameServer == nil {
					return
				}
				var nsStr, profileNsStr, finalNsStr string
				nsStr = windows.UTF16PtrToString(dnsIfSetting.NameServer)
				if dnsIfSetting.ProfileNameServer != nil {
					profileNsStr = windows.UTF16PtrToString(dnsIfSetting.ProfileNameServer)
				}
				if len(nsStr) != 0 {
					finalNsStr += nsStr
				}
				if len(profileNsStr) != 0 {
					finalNsStr += profileNsStr
				}
				ifaceDNSmap[sIf.Alias()] = finalNsStr
			}()
		}
	} else {
		var finalNsStr string
		data, err := wintypes.DnsQueryConfig_DNSServerList()
		if err != nil {
			return nil, err
		}
		for _, v := range data {
			finalNsStr += v.String() + " "
		}
		ifaceDNSmap["Automatic"] = finalNsStr[:len(finalNsStr)-1]
	}
	return ifaceDNSmap, nil
}
