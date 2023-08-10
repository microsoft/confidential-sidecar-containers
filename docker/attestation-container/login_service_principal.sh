#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

DIR_OF_THIS_FILE=$(cd $(dirname $0); pwd)/

function usage {
    set +x
    echo "Usage: $0 <AZURE_TENANT_ID> <AZURE_APP_ID> <AZURE_SERVICE_PRINCIPAL_PASSWORD> <AZURE_SUBSCRIPTION_ID>"
    echo "Options:"
    echo "  -h, --help  Show this help message and exit"
}

# Check for the three required parameters
if [[ $# -lt 4 ]]; then
    echo $#
    usage
    exit 1
fi

AZURE_TENANT_ID="$1"
AZURE_APP_ID="$2"
AZURE_SERVICE_PRINCIPAL_PASSWORD="$3"
AZURE_SUBSCRIPTION_ID="$4"

# Handle sudo
SUDO=""
if [ "$EUID" != 0 ]; then
    SUDO="sudo"
fi

# Login to Azure
if ! command -v az &> /dev/null; then
    curl -sL https://aka.ms/InstallAzureCLIDeb | $SUDO bash
fi

az login --service-principal -u $AZURE_APP_ID -p $AZURE_SERVICE_PRINCIPAL_PASSWORD --tenant $AZURE_TENANT_ID
function wait_10 {
    sleep 10
}
# trap wait_10 EXIT
# set +x
az account show
az account set --subscription "$AZURE_SUBSCRIPTION_ID"

