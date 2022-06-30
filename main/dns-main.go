package main

import (
	"fmt"
	"github.com/kmahyyg/go-network-compo/dns"
)

func main() {
	data, err := dns.Retrieve(false)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	data2, err := dns.Retrieve(true)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(data)
	fmt.Println(data2)
}
