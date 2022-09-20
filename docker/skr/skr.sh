#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [[ -z "${SkrSideCarArgs}" ]]; then
  SkrSideCarArgs=$1
fi

echo SkrSideCarArgs = $SkrSideCarArgs

if [[ -z "${SkrSideCarArgs}" ]]; then
  if /bin/skr -logfile /log.txt; then
    echo "1" > result
  else
    echo "0" > result
  fi
else 
  if /bin/skr -logfile /log.txt -base64 $SkrSideCarArgs; then
      echo "1" > result
  else
      echo "0" > result
  fi
fi
