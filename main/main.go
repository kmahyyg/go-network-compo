package main

import (
	"fmt"
	"github.com/kmahyyg/go-routetable/routes"
)

func main() {
	data, err := routes.Retrieve()
	if err != nil {
		panic(err)
	}
	for _, v := range data {
		fmt.Println(v.ToTableString())
	}
}
