#!/bin/bash
set -e

# Load variables from .env
if [ -f ".env" ]; then
    set -a        # Automatically export all variables
    source .env
    set +a
fi

# Set derived variables
export SUBSCRIPTION_ID=$(az account show --query id -o tsv)
# export PRINCIPAL_ID=0c9fd6ae-7803-4f72-9fdc-2bba252397c1
export PRINCIPAL_ID=$(az identity show \
  --name "$MANAGED_ID_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv)
