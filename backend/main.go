package main

import (
	"flag"
	"fmt"
)

const listenPort string = ":8507"

var (
	Version string
	Revision string
)

// main関数（サーバを開始します）
func main() {
	flag.Parse()

	if flag.Arg(0) == "version" {
		fmt.Println(Version, Revision)
		return
	}

	SetupRouter().Run(listenPort)
}
