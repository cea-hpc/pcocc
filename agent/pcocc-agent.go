package main

import (
	"os"
	"io/ioutil"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.com/onrik/logrus/filename"
)

func locate_serial_port() string {
	// In some lightweight image virt-io ports
	// may not be mapped in /dev/ as done by systemd
	def := "/dev/virtio-ports/pcocc_agent"
	virtiodir := "/sys/class/virtio-ports/"
	if _, err := os.Stat(virtiodir); os.IsNotExist(err) {
		log.Info("Pcocc cannot stat " + virtiodir)
		log.Info("Ignoring serial port detection")
		// Could not scan virt-io ports just asume default
		return def
	}

    files, err := ioutil.ReadDir(virtiodir)
    if err != nil {
		log.Info("Pcocc cannot list :" + virtiodir)
        return def
    }

    for _, file := range files {
		to_check := virtiodir + "/" + file.Name() + "/name"
        dat, err := ioutil.ReadFile(to_check)
		if err != nil {
			continue
		}
		log.Info("Testing " + to_check + " name " + string(dat))
		if string(dat) == "pcocc_agent\n" {
			log.Info("Pcocc serial port found in " + to_check)
			return "/dev/" + file.Name()
		}
    }

	log.Info("No virtio port found resorting to default")
	// Not found
	return def
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
