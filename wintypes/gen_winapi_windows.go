// Code generated by 'go generate'; DO NOT EDIT.

package wintypes

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	moddnsapi   = windows.NewLazySystemDLL("dnsapi.dll")
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procDnsQueryConfig           = moddnsapi.NewProc("DnsQueryConfig")
	procCreateIpForwardEntry2    = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procFreeInterfaceDnsSettings = modiphlpapi.NewProc("FreeInterfaceDnsSettings")
	procFreeMibTable             = modiphlpapi.NewProc("FreeMibTable")
	procGetIfEntry2              = modiphlpapi.NewProc("GetIfEntry2")
	procGetIfTable2              = modiphlpapi.NewProc("GetIfTable2")
	procGetInterfaceDnsSettings  = modiphlpapi.NewProc("GetInterfaceDnsSettings")
	procGetIpForwardEntry2       = modiphlpapi.NewProc("GetIpForwardEntry2")
	procGetIpForwardTable2       = modiphlpapi.NewProc("GetIpForwardTable2")
	procInitializeIpForwardEntry = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procSetIpForwardEntry2       = modiphlpapi.NewProc("SetIpForwardEntry2")
)

func dnsQueryConfig(config DnsConfigType, flag uint32, wsAdapterName uintptr, reserved uintptr, buffer *byte, buflen *uint32) (ret error) {
	r0, _, _ := syscall.Syscall6(procDnsQueryConfig.Addr(), 6, uintptr(config), uintptr(flag), uintptr(wsAdapterName), uintptr(reserved), uintptr(unsafe.Pointer(buffer)), uintptr(unsafe.Pointer(buflen)))
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func createIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procCreateIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func deleteIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procDeleteIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func freeInterfaceDnsSettings(memory unsafe.Pointer) {
	syscall.Syscall(procFreeInterfaceDnsSettings.Addr(), 1, uintptr(memory), 0, 0)
	return
}

func freeMibTable(memory unsafe.Pointer) {
	syscall.Syscall(procFreeMibTable.Addr(), 1, uintptr(memory), 0, 0)
	return
}

func getIfEntry2(row *MibIfRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIfEntry2.Addr(), 1, uintptr(unsafe.Pointer(row)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIfTable2(table **MibIfTable2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIfTable2.Addr(), 1, uintptr(unsafe.Pointer(table)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getInterfaceDnsSettings(iface *windows.GUID, settings *DnsInterfaceSettings) (ret error) {
	r0, _, _ := syscall.Syscall(procGetInterfaceDnsSettings.Addr(), 2, uintptr(unsafe.Pointer(iface)), uintptr(unsafe.Pointer(settings)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func getIPForwardTable2(family AddressFamily, table **mibIPforwardTable2) (ret error) {
	r0, _, _ := syscall.Syscall(procGetIpForwardTable2.Addr(), 2, uintptr(family), uintptr(unsafe.Pointer(table)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func initializeIPForwardEntry(route *MibIPforwardRow2) {
	syscall.Syscall(procInitializeIpForwardEntry.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	return
}

func setIPForwardEntry2(route *MibIPforwardRow2) (ret error) {
	r0, _, _ := syscall.Syscall(procSetIpForwardEntry2.Addr(), 1, uintptr(unsafe.Pointer(route)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}
