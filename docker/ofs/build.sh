#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e
pushd $(dirname $0)

# This script builds the overlay filesystem container

docker build --tag ofs -f Dockerfile.ofs ../..

# clean up
popd
