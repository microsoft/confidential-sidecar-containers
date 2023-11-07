#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -e
pushd $(dirname $0)

docker build -t skr -f Dockerfile.skr ../..
popd