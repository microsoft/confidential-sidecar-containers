#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [[ -z "${AttestClientRuntimeData}" ]]; then
  AttestClientRuntimeData=$1
fi

echo AttestClientRuntimeData = $AttestClientRuntimeData

while true; do
  curl -X POST -H 'Content-Type: application/json' -d "{\"runtime_data\": \"$AttestClientRuntimeData\"}" http://localhost:8080/attest/json > /jsonreport.out;
  sleep 5;
done
