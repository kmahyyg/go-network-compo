package routes

import (
	"errors"
	"fmt"
)

func bytes2IPv4(b [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func bytes2HWAddr_MACAddr(b []byte) string {
	if len(b) != 6 {
		panic(errors.New("not a valid network interface hardware addr"))
	}
	return fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", b[0], b[1], b[2], b[3], b[4], b[5])
}
