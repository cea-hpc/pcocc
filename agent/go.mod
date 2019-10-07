module pcocc-agent

go 1.13

replace github.com/cea-hpc/pcocc/agent/agent_protocol => ./agent_protocol

require (
	github.com/cea-hpc/pcocc/agent/agent_protocol v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.3.2
	github.com/kr/pty v1.1.8
	github.com/onrik/logrus v0.4.1
	github.com/sirupsen/logrus v1.4.2
)
