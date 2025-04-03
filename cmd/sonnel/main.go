package main

import (
	"log"
	"os"

	"github.com/gleicon/sonnel/cmd/sonnel/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
