#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e
pushd $(dirname $0)

# This script builds the encrypted filesystem container

docker build --tag encfs -f Dockerfile.encfs ../..

# clean up
popd
