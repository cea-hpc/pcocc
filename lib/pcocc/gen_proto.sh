python -m grpc_tools.protoc --proto_path=./ --python_out=./ --grpc_python_out=./ ./agent.proto

if test "x$?" = "x0"
then
    echo "Generation succeeded"
else
    echo "Error generating GRPC interface"
fi
