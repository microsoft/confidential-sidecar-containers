#!/bin/sh

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

# Use this to check everything is populated correctly
print_env() {
    echo "Environment variables set..."
	echo "SUBSCRIPTION_ID = $SUBSCRIPTION_ID"
	echo "MANAGED_ID_NAME = $MANAGED_ID_NAME"
	echo "RESOURCE_GROUP  = $RESOURCE_GROUP"
	echo "PRINCIPAL_ID    = $PRINCIPAL_ID"
	echo "USER_ID         = $USER_ID"
	echo "VAULT_NAME      = $VAULT_NAME"
	echo "KEY_NAME        = $KEY_NAME"
	echo "REGION          = $REGION"
	echo "TEMPLATE_PATH   = $TEMPLATE_PATH"
}
