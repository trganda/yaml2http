package main

import (
	"flag"
	"fmt"

	"trganda.com/yaml2http/lib"
)

func main() {

	path := flag.String("path", "", "path to poc file.")
	flag.Parse()

	poc, err := lib.LoadPoc(*path)
	if err != nil {
		fmt.Println(err)
	}

	requests, err := lib.ToHttpRequest(poc)
	if err != nil {
		fmt.Printf("[-] convert to http request failed. err: %v\n", err)
	}
	for _, request := range *requests {
		str, err := request.ToHttpRequestText()
		if err != nil {
			fmt.Printf("[-] generate http request text failed. err %v\n", err)
		}
		fmt.Println(str)
	}
}
