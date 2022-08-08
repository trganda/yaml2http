package main

import (
	"fmt"

	"trganda.com/yaml2http/lib"
)

func main() {
	fmt.Println("1")
	poc, err := lib.LoadPoc("pocs/a.yaml")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(poc.Name)
}
