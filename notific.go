package main

import (
	"flag"
	"github.com/xmjw/api.notific.io/notific"
	"log"
)

// Entry point.
func main() {
	flag.Parse()
	log.Println("Starting up api.notific.io")
	go notific.ApiServer()
}
