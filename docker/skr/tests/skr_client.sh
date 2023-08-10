#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [ -z "${SkrClientMAAEndpoint}" ]; then
  SkrClientMAAEndpoint=$1
fi

echo SkrClientMAAEndpoint = $SkrClientMAAEndpoint

if [ -z "${SkrClientAKVEndpoint}" ]; then
  SkrClientAKVEndpoint=$2
fi

echo SkrClientAKVEndpoint = $SkrClientAKVEndpoint

if [ -z "${SkrClientKID}" ]; then
  SkrClientKID=$3
fi

echo SkrClientKID = $SkrClientKID

while true; do 
  curl -X POST -H 'Content-Type: application/json' -d "{\"maa_endpoint\": \"$SkrClientMAAEndpoint\", \"akv_endpoint\": \"$SkrClientAKVEndpoint\", \"kid\": \"$SkrClientKID\"}" http://localhost:8080/key/release > /keyrelease.out;
  cat /keyrelease.out;
  sleep 5;
done
