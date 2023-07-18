#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e
pushd $(dirname $0)

# This script builds the encrypted filesystem container

mkdir -p bin
pushd bin
echo building azmount
CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/azmount
echo building remotefs
CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/remotefs
popd 

echo building get-snp-report
pushd ../../tools/get-snp-report
make 
popd
cp ../../tools/get-snp-report/bin/get-snp-report ./bin
cp ../../tools/get-snp-report/bin/get-fake-snp-report ./bin

docker build --tag encfs -f Dockerfile.encfs .

# clean up
rm -rf bin
popd
