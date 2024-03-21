# Based on https://hub.docker.com/_/golang/

# To build this:
#   cd <project root directory> # It's necessary to copy contents of parent directory
#   docker build -t attestation-container -f docker/attestation-container/Dockerfile . [--build-arg variant=dev]

# Two variants: run (production) or dev (development)
ARG variant=run

# Build
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.22.1-fips-cbl-mariner2.0 AS builder-app
WORKDIR /usr/src/app

# Set environment variables for golang fips build
# https://github.com/microsoft/go/tree/microsoft/main/eng/doc/fips#usage-build
# using allowcryptofallback to allow use of non-fips crypto since not directly using openssl in code and otherwise causes a seg fault
ENV GOOS=linux CGO_ENABLED=0 GOEXPERIMENT=systemcrypto,allowcryptofallback

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY . .
RUN go mod download && go mod verify

RUN go build -v -o /usr/local/bin/app ./cmd/attestation-container/

FROM builder-app AS builder-test
WORKDIR /usr/src/app
RUN pushd cmd/attestation-container && CGO_ENABLED=0 go test -c -cover && popd && pushd pkg/attest && CGO_ENABLED=0 go test -c -cover && popd && pushd pkg/common && CGO_ENABLED=0 go test -c -cover

# Run
FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0 AS app-run
COPY --from=builder-app /usr/local/bin/app /usr/local/bin/app

FROM app-run AS app-dev
COPY --from=builder-test /usr/src/app/cmd/attestation-container/attestation-container.test* /usr/local/bin/attestation-container.test 
COPY --from=builder-test /usr/src/app/pkg/attest/attest.test* /usr/local/bin/attest.test 
COPY --from=builder-test /usr/src/app/pkg/common/security-context-test/* /security-context-test/
COPY --from=builder-test /usr/src/app/pkg/common/common.test* /usr/local/bin/common.test 

# Final 
FROM app-${variant} AS final
CMD ["app"]
