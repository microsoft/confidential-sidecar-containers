#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

if [[ -z "${EncfsSideCarArgs}" ]]; then
  EncfsSideCarArgs=$1
fi

echo EncfsSideCarArgs = $EncfsSideCarArgs

if [[ -z "${LogFile}" ]]; then
  LogFile=$2
fi

echo LogFile = $LogFile

if [[ -z "${LogLevel}" ]]; then
  LogLevel=$3
fi

echo LogLevel = $LogLevel

if [[ -z "${EncfsSideCarArgs}" ]]; then
  if /bin/remotefs -logfile $LogFile -loglevel $LogLevel; then
    echo "1" > result
  else
    echo "0" > result
  fi
else
  if /bin/remotefs -logfile $LogFile -loglevel $LogLevel -base64 $EncfsSideCarArgs; then
    echo "1" > result
  else
    echo "0" > result
  fi
fi

# Wait forever
sleep infinity
