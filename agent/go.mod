module pcocc-agent

go 1.13

replace github.com/cea-hpc/pcocc/agent/agent_protocol => ./agent_protocol

require (
	github.com/cea-hpc/pcocc/agent/agent_protocol v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.3.2
	github.com/kr/pretty v0.3.0 // indirect
	github.com/kr/pty v1.1.8
	github.com/onrik/logrus v0.9.0
	github.com/rogpeppe/go-internal v1.8.0 // indirect
	github.com/sirupsen/logrus v1.9.4
	github.com/tidwall/gjson v1.14.4 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
