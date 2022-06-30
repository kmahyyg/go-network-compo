package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

func Bytes2IPv4(b [4]byte, isLinux bool) string {
	if isLinux {
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func Bytes2HWAddr_MACAddr(b []byte) string {
	if len(b) != 6 {
		panic(errors.New("not a valid network interface hardware addr"))
	}
	return fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func DeduplicateStrInSlice(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func Uint32ToNetIP_LittleEndian(data uint32) (ip4 net.IP) {
	ip4 = make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip4, data)
	return
}
