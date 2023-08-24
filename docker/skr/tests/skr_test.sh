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

if [ -z "${TestingMismatchedTCB}" ]; then
  TestingMismatchedTCB=$2
fi

echo CorruptedTcbm = $TestingMismatchedTCB

if [ -n "${TestingMismatchedTCB}" ]; then
  CmdlineArgs="${CmdlineArgs} -allowTestingMismatchedTCB=${TestingMismatchedTCB}"
fi

if [ -z "${Port}" ]; then
  Port=$3
fi

echo Port = $Port

if [ -n "${Port}" ]; then
  CmdlineArgs="${CmdlineArgs} -port ${Port}"
fi

echo CmdlineArgs = $CmdlineArgs

if /bin/skr $CmdlineArgs; then
  echo "1" > result
else
  echo "0" > result
fi
