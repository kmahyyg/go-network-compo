//go:build windows

package dns

import (
	"github.com/kmahyyg/go-network-compo/wintypes"
	"golang.org/x/sys/windows"
	"strings"
)

func Retrieve() (string, error) {
	// Fetch all Interfaces
	ifaces, err := wintypes.GetIfTable2()
	if err != nil {
		return "", err
	}
	var sb strings.Builder
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
			var nsStr, profileNsStr string
			nsStr = windows.UTF16PtrToString(dnsIfSetting.NameServer)
			if dnsIfSetting.ProfileNameServer != nil {
				profileNsStr = windows.UTF16PtrToString(dnsIfSetting.ProfileNameServer)
			}
			if len(nsStr) != 0 {
				sb.WriteString(nsStr + " [" + sIf.Alias() + "]\n")
			}
			if len(profileNsStr) != 0 {
				sb.WriteString(profileNsStr + " [" + sIf.Alias() + "]\n")
			}
		}()
	}
	return sb.String(), nil
}
