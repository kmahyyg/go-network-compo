//go:build windows && (386 || arm)

package routes

// Types defined here ONLY works for 32-bit.
// Code from wireguard is licensed under MIT.
// Totally Grabbed from https://github.com/wireguard/wireguard-windows , tunnel/winipcfg/types.go

// mibIPforwardTable2 structure contains a table of IP route entries.
// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/ns-netioapi-_mib_ipforward_table2
type mibIPforwardTable2 struct {
	numEntries uint32
	_          [4]byte
	table      [anySize]MibIPforwardRow2
}
