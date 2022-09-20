#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [[ -z "${EncfsSideCarArgs}" ]]; then
  EncfsSideCarArgs=$1
fi

echo EncfsSideCarArgs = $EncfsSideCarArgs

if [[ -z "${EncfsSideCarArgs}" ]]; then
  if /bin/remotefs -logfile /log.txt; then
    echo "1" > result
  else
    echo "0" > result
  fi
else
  if /bin/remotefs -logfile /log.txt -base64 $EncfsSideCarArgs; then
    echo "1" > result
  else
    echo "0" > result
  fi
fi

# Wait forever
while true; do sleep 1; done
