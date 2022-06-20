package routes

import "fmt"

func bytes2IPv4(b [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
