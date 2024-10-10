#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Important note: This script is meant to run from inside the container

CmdlineArgs=""

# we expect all the arguments to be passed in as environment variables, if at all
if [ -n "${VHDMount}" ]; then
  CmdlineArgs="${CmdlineArgs} -vhdmount ${VHDMount}"
fi

if [ -n "${ScratchMount}" ]; then
  CmdlineArgs="${CmdlineArgs} -scratchmount ${ScratchMount}"
fi

if [ -n "${OverlayMount}" ]; then
  CmdlineArgs="${CmdlineArgs} -overlaymount ${OverlayMount}"
fi

if [ -n "${LogFile}" ]; then
  CmdlineArgs="${CmdlineArgs} -logfile ${LogFile}"
fi

if [ -n "${LogLevel}" ]; then
  CmdlineArgs="${CmdlineArgs} -loglevel ${LogLevel}"
fi

echo CmdlineArgs = $CmdlineArgs

if /bin/overlayfs $CmdlineArgs; then
  echo "1" > result
else
  echo "0" > result
fi

# Wait forever
while true; do sleep 1; done
