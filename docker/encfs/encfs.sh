#!/bin/bash

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

cleanup_unmount() {
  mount_array=$(process_encoded_string $EncfsSideCarArgs)
  echo "Cleaning up by unmounting the following remote filesystem folder."
  for mount_point in "${mount_array[@]}"; do
    echo "attempting to unmount $mount_point"
    umount $mount_point 2>&1
    if [ $? -eq 0 ]; then
      echo "Unmounting was successful."
    else
      echo "Unmounting failed with exit status $exit_status."
    fi
  done
}

process_encoded_string() {
    local encoded_string="$1"
    decoded_string=$(echo "$encoded_string" | base64 -d)
    declare -A set

    # Check if the decoded string is a valid JSON
    if echo "$decoded_string" | jq empty 2>/dev/null; then
        # Store the JSON object in an array
        json_array=("$decoded_string")
        
        mount_points=($(echo "$json_array" | jq -r '.azure_filesystems[].mount_point'))
        for mount_point in "${mount_points[@]}"; do
            mount_point="${mount_point%/*}"
            for folder in "$mount_point"/.*; do
                if [[ -d "$folder" && $folder =~ "$mount_point"/.filesystem-[0-99]* ]]; then
                  set["$folder"]=1
                fi
            done
        done
        keys=("${!set[@]}")
        echo "${keys[@]}"
    else
        echo "Error: The decoded string is not a valid JSON object."
        exit 1 
    fi
}

# Trap SIGTERM
trap 'cleanup_unmount; exit 0' SIGTERM

if /bin/remotefs $CmdlineArgs; then
  echo "1" > result
else
  echo "0" > result
fi

# Wait forever
while true; do sleep 1; done
