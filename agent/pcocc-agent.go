package main

import (
	"os"
	"io/ioutil"
	"flag"
	"path"
	log "github.com/sirupsen/logrus"
	"github.com/onrik/logrus/filename"
)

func locate_serial_port() string {
	// Since we may run on minimal systems where udev might not be
	// used, we detect virtio-ports ourselves
	virtiodir := "/sys/class/virtio-ports/"
	if _, err := os.Stat(virtiodir); os.IsNotExist(err) {
		log.Fatal("Cannot stat " + virtiodir)
		os.Exit(1)
	}

	files, err := ioutil.ReadDir(virtiodir)
	if err != nil {
		log.Fatal("Failed to read directory " + virtiodir)
		os.Exit(1)
	}

	for _, file := range files {
		to_check := path.Join(virtiodir, file.Name(), "name")
		dat, err := ioutil.ReadFile(to_check)
		if err != nil {
			continue
		}

		if string(dat) == "pcocc_agent\n" {
			log.Info("pcocc serial port found in " + to_check)
			return path.Join("/dev", file.Name())
		}
	}

	log.Fatal("pcocc agent virtio port not found")
	os.Exit(1)

	return "unreachable code"
}


func main() {
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}
	log.AddHook(filename.NewHook())

	port := locate_serial_port()
	ser := ReaderMake(port)
	ser.ListenLoop()
	return
}
