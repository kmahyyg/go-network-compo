//go:build windows

package dns

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output gen_netioapi_windows.go prototype_netioapi_windows.go
