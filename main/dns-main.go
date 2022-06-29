package main

import (
	"fmt"
	"github.com/kmahyyg/go-network-compo/dns"
)

func main() {
	data, err := dns.Retrieve()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(data)
}
