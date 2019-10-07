package main

import (
	"os"
	"io"
	"strings"
	"time"
	"encoding/base64"
	"strconv"
	"github.com/cea-hpc/pcocc/agent/agent_protocol"
	proto "github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

/*Reader this reads commands from a serial port */
type Reader struct {
	path    string
	frozen  bool
}

/*ReaderMake this create a serial reader */
func ReaderMake(p string) Reader {
	var sr = Reader{
		path:    p,
	}
	return sr
}

func (sr *Reader) handleClientInput(f *os.File, inc chan *agent_protocol.AgentMessage, thawc chan bool) error {
	defer f.Close()

	err := error(nil)
	leftover := ""

	bytes_read := make([]byte, 4194304)

	for {
		n, err := f.Read(bytes_read)

		if err == io.EOF {
			if sr.frozen == true {
				log.Info("EOF while frozen, wait before retrying")
				time.Sleep(10 * time.Second)
				continue
			} else {
				log.Warning("Abandon loop due to EOF")
				break
			}
		}

		data := string(bytes_read[:n])

		fields := strings.Split(data, "\n")
		l := len(fields)

		for i := 0; i < l-1; i++ {
			thismsg, err :=  base64.StdEncoding.DecodeString(leftover + fields[i])
			leftover = ""

			if err != nil {
				log.Error("Could not decode base64", err)
				continue
			}

			msg := &agent_protocol.AgentMessage{}
			if err := proto.Unmarshal(thismsg, msg); err != nil {
				log.Error("Could not unmarshal protobuf: ", err)
				continue
			}

			log.Debug("Received message: ", msg.Name)
			if msg.Name == "thaw" {
				log.Info("Thaw message received,  unfreezing")
				thawc <- true
				sr.frozen = false
			}

			inc <- msg
		}

		if data[len(data) - 1] != '\n' {
			leftover += fields[l-1]
		}
	}

	close(inc)

	return err
}

func (sr *Reader) write(f *os.File, b []byte) error {
	for len(b) > 0 {
		n, err := f.Write(b)
		if n == 0 && err != nil {
			log.Error("Could not write to serial port: ", err)
			return err
		}
		log.Debug("Written " +  strconv.Itoa(n) +  " out of "+ strconv.Itoa(len(b)) + " bytes to serial port")
		b = b[n:]
	}

	return nil
}

/*ListenLoop Start waiting for clients */
func (sr *Reader) ListenLoop() {
	for {
		f, err := os.OpenFile(sr.path, os.O_RDWR, 0600)

		if err != nil {
			log.Error(err)
			time.Sleep(1 * time.Second)
			continue
		}

		/* The only way for now to make sure a client is
		   here by just blocking on a write */
		err = sr.write(f, []byte("\n"))

		if err != nil {
			log.Error(err)
			f.Close()
			continue
		}

		log.Info("Client connected")

		var inchan     = make(chan *agent_protocol.AgentMessage)
		var outchan    = make(chan *agent_protocol.AgentMessage)
		var thawchan   = make(chan bool)

		go sr.handleClientInput(f, inchan, thawchan)

		var disp = MakeDispatch(inchan, outchan)
		go disp.Run()

		select_outchan := outchan

		for {
			select {
			case msg, ok := <- select_outchan:
				if !ok {
					log.Debug("Output channel closed")
					break
				}

				log.Debug("Sending message: ", msg.Name)
				protomsg, err := proto.Marshal(msg)
				if err != nil {
					log.Error("Could not Marshal protobuf: ", err)
					continue
				}

				b64msg :=  base64.StdEncoding.EncodeToString(protomsg)
				err = sr.write(f, []byte(b64msg + "\n"))
				if err != nil {
					continue
				}

				if msg.Name == "freeze" {
					log.Debug("Freezing output")
					select_outchan = nil
					sr.frozen = true
				}
			case _ = <- thawchan:
				log.Info("Resuming output")
				select_outchan = outchan
			}
		}
		f.Close()
	}

}
