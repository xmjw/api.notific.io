package main

import (
	"flag"
	"log"
	"github.com/xmjw/api.notific.io/notific"
)

// Entry point.
func main() {
	flag.Parse()
	log.Println("Starting up api.io")
	notific.WebServer()
}
