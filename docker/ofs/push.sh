#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -e

# This script pushes the encrypted filesystem container to a registry

# $1 remote registry name (e.g., myregistry)
# $2 remote registry domain (e.g., azurecr.io)
# $3 container_name:container:version (e.g., ofs:1.1)
# $4 --skip-login flag

if ! [ -n "$4" ] || [ "$4" != "--skip-login" ]; then
    az acr login --name $1 
fi
docker tag ofs $1.$2/$3
docker push $1.$2/$3
