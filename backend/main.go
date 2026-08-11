package main

import (
	"flag"
	"fmt"
)

const LISTEN_PORT string = ":8507"

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

	SetupRouter().Run(LISTEN_PORT)
}
