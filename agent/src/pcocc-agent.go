package main

import (
	"serial"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.com/onrik/logrus/filename"
)

func main() {
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}
	log.AddHook(filename.NewHook())

	ser := serial.ReaderMake("/dev/virtio-ports/pcocc_agent")
	ser.ListenLoop()
	return
}
