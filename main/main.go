package main

import "github.com/kmahyyg/go-routetable/routes"

func main() {
	_, err := routes.Retrieve()
	if err != nil {
		panic(err)
	}
}
