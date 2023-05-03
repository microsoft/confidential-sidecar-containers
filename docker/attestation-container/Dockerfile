# Based on https://hub.docker.com/_/golang/

# To build this:
#   cd <project root directory> # It's necessary to copy contents of parent directory
#   docker build -t attestation-container -f docker/attestation-container/Dockerfile . [--build-arg variant=dev]

# Two variants: run (production) or dev (development)
ARG variant=run

# Build
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.20-fips-cbl-mariner2.0 AS builder-app
WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY . .
RUN go mod download && go mod verify

# Note: Use CGO_ENABLED=0 to build statically-linked binaries deployable in scratch image
RUN CGO_ENABLED=0 go build -v -o /usr/local/bin/app ./cmd/attestation-container/

FROM builder-app AS builder-test
WORKDIR /usr/src/app
## Pre-compile tests to avoid I/O errors in ACI
RUN pushd cmd/attestation-container && CGO_ENABLED=0 go test -c && popd && pushd pkg/attest && CGO_ENABLED=0 go test -c && popd && pushd pkg/uvm && CGO_ENABLED=0 go test -c

# Run
FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0 AS app-run
COPY --from=builder-app /usr/local/bin/app /usr/local/bin/app

FROM app-run AS app-dev
COPY --from=builder-test /usr/src/app/cmd/attestation-container/attestation-container.test* /usr/local/bin/attestation-container.test 
COPY --from=builder-test /usr/src/app/pkg/attest/attest.test* /usr/local/bin/attest.test 
COPY --from=builder-test /usr/src/app/pkg/attest/testdata/host_amd_certificate_env* /testdata/
COPY --from=builder-test /usr/src/app/pkg/uvm/uvm.test* /usr/local/bin/uvm.test 

# Final 
FROM app-${variant} AS final
CMD ["app"]
