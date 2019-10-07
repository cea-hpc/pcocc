#! /bin/bash

if [[ ! -d proto ]] || [[ ! -d agent ]] || [[ ! -d lib/pcocc ]]; then
    echo "Please run this script from the root of the pcocc repository" >&2
    exit 1
fi


python -m grpc_tools.protoc --proto_path=./proto/ --python_out=./lib/pcocc --grpc_python_out=./lib/pcocc ./proto/agent.proto

if [[ "$?" -eq 0 ]]; then
    echo "Python generation succeeded"
else
    echo "Error generating python GRPC interface" >&2
fi

hash protoc >/dev/null 2>&1  || { echo "Please install protoc"  ; exit 1; }
hash protoc-gen-go >/dev/null 2>&1  || { echo "Please install protoc-gen-go" ; exit 1;}

protoc -I="$PWD/proto" --go_out="$PWD/agent/src/agent_protocol/" "$PWD/proto/agent.proto"

if [[ "$?" -eq 0 ]]; then
    echo "Go generation succeeded"
else
    echo "Error generating go GRPC interface" >&2
fi
