//go:build windows

package wintypes

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output gen_winapi_windows.go prototype_winapi_windows.go
