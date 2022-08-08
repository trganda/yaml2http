package main

import (
	"fmt"

	"trganda.com/yaml2http/lib"
)

func main() {
	poc, err := lib.LoadPoc("pocs/a.yaml")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(poc)
}
