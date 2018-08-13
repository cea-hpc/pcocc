GOCC="go"
FILES=./src/pcocc-agent.go ./src/command/command.go ./src/serial/serial.go ./src/agent_protocol/agent.pb.go

all : pcocc-agent

pcocc-agent : $(FILES)
	GOPATH=$(PWD) go get github.com/sirupsen/logrus
	GOPATH=$(PWD) go get github.com/onrik/logrus/filename
	GOPATH=$(PWD) go build ./src/pcocc-agent.go

install:
	mkdir -p ${DESTDIR}/sbin/
	mkdir -p ${DESTDIR}/etc/systemd/system/
	install -m 755 pcocc-agent ${DESTDIR}/sbin
	install -m 644 pcocc-agent.service ${DESTDIR}/etc/systemd/system/

clean:
	rm -fr pcocc-agent
