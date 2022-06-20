//go:build windows && (amd64 || arm64)

package routes

// Types defined here ONLY works for 64-bit.
// Code from wireguard is licensed under MIT.
// Totally Grabbed from https://github.com/wireguard/wireguard-windows , tunnel/winipcfg/types.go

// mibIPforwardTable2 structure contains a table of IP route entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_table2
type mibIPforwardTable2 struct {
	numEntries uint32
	table      [anySize]MibIPforwardRow2
}
