#!/bin/bash

# Load variables from .env
if [ -f ".env" ]; then
    set -a        # Automatically export all variables
    source .env
    set +a
fi

# Set derived variables
export SUBSCRIPTION_ID=$(az account show --query id -o tsv)

export PRINCIPAL_ID=$(az identity show \
  --name "$MANAGED_ID_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv)

export USER_ID=$(az ad signed-in-user show --query id -o tsv)