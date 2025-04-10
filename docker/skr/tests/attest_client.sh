#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [ -z "${AttestClientRuntimeData}" ]; then
  AttestClientRuntimeData=$1  
fi


echo AttestClientRuntimeData = $AttestClientRuntimeData

if [ -z "${AttestClientMAAEndpoint}" ]; then
  AttestClientMAAEndpoint=$2
fi

echo AttestClientMAAEndpoint = $AttestClientMAAEndpoint

while true; do
  if [ -z "${AttestClientMAAEndpoint}" ]; then
    curl -X POST -H 'Content-Type: application/json' -d "{\"runtime_data\": \"$AttestClientRuntimeData\"}" http://localhost:8080/attest/raw > /raw.out;  
    curl -X POST -H 'Content-Type: application/json' -d "{\"runtime_data\": \"$AttestClientRuntimeData\"}" http://localhost:8080/attest/combined > /combined.out;  
  else
    curl -X POST -H 'Content-Type: application/json' -d "{\"maa_endpoint\": \"$AttestClientMAAEndpoint\", \"runtime_data\": \"$AttestClientRuntimeData\"}" http://localhost:8080/attest/maa > /maatoken.out; 
  fi
  sleep 5;
  ls -l *.out
done
ls -l *.