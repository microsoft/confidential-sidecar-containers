#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

echo building get-snp-report
pushd ../../tools/get-snp-report
make 
popd
cp ../../tools/get-snp-report/bin/verbose-report .