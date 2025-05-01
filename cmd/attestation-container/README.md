# Attestation Container

This is a gRPC server application to fetch SEV-SNP attestation, platform certificates, and UVM endorsemens.

## Environment

This application needs to run on [SEV-SNP VM](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf).

## Dependencies

- [Go](https://go.dev/doc/install)
- [gRPC](https://grpc.io/docs/languages/go/quickstart/)

## How to start the app

The following command starts the gRPC server application (must be inside SEV-SNP VM).

```bash
# In the same directory as this README.md
go run .
```

You can use insecure virtual mode to run the application on non SEV-SNP VM.
(**Not secure. Do not use it in production**).

```bash
go run . --insecure-virtual
```

You can find the details of the flag and other flags by running `go run . --help`.

## Build

Since it's a go application, you can build the application before running it.

```bash
go build
./attestation-container
```

## API

The gPRC API is defined in [attestation-container.proto](https://github.com/microsoft/confidential-sidecar-containers/tree/main/cmd/attestation-container/protobuf/attestation-container.proto).

Note that gPRC communication is used over [Unix domain sockets (UDS)](https://en.wikipedia.org/wiki/Unix_domain_socket) in order to make sure only processes on the same UVM can get an attestation report.
You can find an example client code in [the E2E test](https://github.com/microsoft/confidential-sidecar-containers/tree/main/cmd/attestation-container/attestation-container_test.go).

## Test

```bash
# Run the app first
go run .

# In another terminal
go test
```

## Development and maintenance

### Update protobuf

When you edit `.proto` file, you also need to update `.pb.go` files by:

```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative protobuf/attestation-container.proto
```
