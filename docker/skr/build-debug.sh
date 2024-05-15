#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e
pushd $(dirname $0)

# This script builds the binaries and sets up the docker image

mkdir -p ../../bin
pushd ../../bin
CGO_ENABLED=0 GOOS=linux go build github.com/Microsoft/confidential-sidecar-containers/cmd/skr
popd

pushd ../../tools/get-snp-report
make
popd

cp ../../tools/get-snp-report/bin/get-snp-report ../../bin/
cp ../../tools/get-snp-report/bin/get-fake-snp-report ../../bin/
cp ../../tools/get-snp-report/bin/verbose-report ../../bin/

docker build --tag skr -f Dockerfile.debug ../..

# cleanup
rm -rf bin
popd
