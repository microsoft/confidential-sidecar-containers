FROM python:latest
WORKDIR /usr/src/app

RUN pip install flask grpcio grpcio-tools
COPY cmd/attestation-container/protobuf/attestation-container.proto .
RUN python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. attestation-container.proto

COPY tests/attestation/primary.py .

CMD ["python3", "primary.py"]