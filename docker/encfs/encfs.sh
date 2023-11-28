#!/bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

CmdlineArgs=""

# we expect all the arguments to be passed in as environment variables, if at all
if [ -n "${EncfsSideCarArgs}" ]; then
  CmdlineArgs="${CmdlineArgs} -base64 ${EncfsSideCarArgs}"
fi

if [ -n "${LogFile}" ]; then
  CmdlineArgs="${CmdlineArgs} -logfile ${LogFile}"
fi

if [ -n "${LogLevel}" ]; then
  CmdlineArgs="${CmdlineArgs} -loglevel ${LogLevel}"
fi

echo CmdlineArgs = $CmdlineArgs

if /bin/remotefs $CmdlineArgs; then
  echo "1" > result
else
  echo "0" > result
fi

# Wait forever
sleep infinity
