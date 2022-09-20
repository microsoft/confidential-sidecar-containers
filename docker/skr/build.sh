#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# This script builds the binaries and sets up the docker image

mkdir bin
pushd bin
CGO_ENABLED=0 GOOS=linux go build github.com/microsoft/confidential-sidecars/cmd/skr
popd

pushd ../../tools/get-snp-report
make 
popd

cp ../../tools/get-snp-report/bin/get-snp-report ./bin
cp ../../tools/get-snp-report/bin/get-fake-snp-report ./bin

docker build --tag skr -f Dockerfile.skr .

# cleanup
rm -r bin