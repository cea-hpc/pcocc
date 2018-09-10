GOCC="go"
FILES=./src/pcocc-agent.go ./src/command/command.go ./src/serial/serial.go ./src/agent_protocol/agent.pb.go

PROTO=$(PWD)/../lib/pcocc/agent.proto

all : pcocc-agent

protocol: $(PROTO)
	# Get To get PROTOC
	# https://github.com/protocolbuffers/protobuf
	GOPATH=$(PWD) go get -u github.com/golang/protobuf/protoc-gen-go
	protoc -I=`dirname $(PROTO)` --go_out=$(PWD)/src/agent_protocol/ $(PROTO)

pcocc-agent : $(FILES) protocol
	GOPATH=$(PWD) go get github.com/sirupsen/logrus
	GOPATH=$(PWD) go get github.com/onrik/logrus/filename
	GOPATH=$(PWD) go get github.com/golang/protobuf/proto
	GOPATH=$(PWD) go get github.com/kr/pty
	GOPATH=$(PWD) go get github.com/golang/protobuf/proto
	GOPATH=$(PWD) go build ./src/pcocc-agent.go

install:
	mkdir -p ${DESTDIR}/sbin/
	mkdir -p ${DESTDIR}/etc/systemd/system/
	install -m 755 pcocc-agent ${DESTDIR}/sbin
	install -m 644 pcocc-agent.service ${DESTDIR}/etc/systemd/system/

clean:
	rm -fr pcocc-agent
