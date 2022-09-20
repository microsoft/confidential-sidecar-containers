#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [[ -z "${SkrClientMAAEndpoint}" ]]; then
  SkrClientMAAEndpoint=$1
fi

echo SkrClientMAAEndpoint = $SkrClientMAAEndpoint

if [[ -z "${SkrClientMHSMEndpoint}" ]]; then
  SkrClientMHSMEndpoint=$2
fi

echo SkrClientMHSMEndpoint = $SkrClientMHSMEndpoint

if [[ -z "${SkrClientKID}" ]]; then
  SkrClientKID=$3
fi

echo SkrClientKID = $SkrClientKID

while true; do 
  curl -X POST -H 'Content-Type: application/json' -d "{\"maa_endpoint\": \"$SkrClientMAAEndpoint\", \"mhsm_endpoint\": \"$SkrClientMHSMEndpoint\", \"kid\": \"$SkrClientKID\"}" http://localhost:8080/key/release > /keyrelease.out;
  cat /keyrelease.out;
  sleep 5;
done
