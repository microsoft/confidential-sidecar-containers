#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# This script builds all binaries

mkdir bin
pushd bin
echo building skr
CGO_ENABLED=0 GOOS=linux go build github.com/microsoft/confidential-sidecars/cmd/skr
echo building azmount
CGO_ENABLED=0 GOOS=linux go build github.com/microsoft/confidential-sidecars/cmd/azmount
echo building remotefs
CGO_ENABLED=0 GOOS=linux go build github.com/microsoft/confidential-sidecars/cmd/remotefs
popd

echo building get-snp-report
pushd tools/get-snp-report
make 
popd
cp tools/get-snp-report/bin/get-snp-report ./bin
cp tools/get-snp-report/bin/get-fake-snp-report ./bin

pushd docker/encfs
bash ./build.sh
popd

pushd docker/skr
bash ./build.sh
popd
