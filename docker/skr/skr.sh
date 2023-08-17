#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

CmdlineArgs="-logfile ./log.txt"

if [ -z "${SkrSideCarArgs}" ]; then
  SkrSideCarArgs=$1
fi

echo SkrSideCarArgs = $SkrSideCarArgs

if [ -n "${SkrSideCarArgs}" ]; then
  CmdlineArgs="${CmdlineArgs} -base64 ${SkrSideCarArgs}"
fi

if [ -z "${Port}" ]; then
  Port=$2
fi

echo Port = $Port

if [ -n "${Port}" ]; then
  CmdlineArgs="${CmdlineArgs} -port ${Port}"
fi

if [[ -z "${LogLevel}" ]]; then
  LogLevel=$3
fi

echo LogLevel = $LogLevel

if [ -n "${LogLevel}" ]; then
  CmdlineArgs="${CmdlineArgs} -port ${LogLevel}"
fi

echo CmdlineArgs = $CmdlineArgs

if /bin/skr $CmdlineArgs; then
  echo "1" > result
else
  echo "0" > result
fi
