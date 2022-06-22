package main

import (
	"fmt"
	"github.com/kmahyyg/go-routetable/routes"
)

func main() {
	data, err := routes.Retrieve()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	for _, v := range data {
		fmt.Println(v.ToTableString())
	}
}
