package main

import (
	"flag"
	"log"

	"trganda.com/yaml2http/lib"
)

func main() {

	path := flag.String("path", "", "path to poc file.")
	flag.Parse()

	poc, err := lib.LoadPoc(*path)
	if err != nil {
		log.Fatalf("[-] loading poc file %s error. err: %v\n", *path, err)
	}

	requests, err := lib.ToHttpRequest(poc)
	if err != nil {
		log.Fatalf("[-] convert to http request failed. err: %v\n", err)
	}
	for _, request := range *requests {
		str, err := request.ToHttpRequestText()
		if err != nil {
			log.Fatalf("[-] generate http request text failed. err %v\n", err)
		}
		log.Printf("[+] generated\n%v\n", str)
	}
}
