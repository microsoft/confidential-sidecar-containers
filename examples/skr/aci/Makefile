include .env.mk


# --------------------------------------------------
# Use `make env` to check your current variables
# --------------------------------------------------
env:
	@echo "Environment variables from '.env.mk':"
	@echo "  REGION          = $(REGION)"
	@echo "  MANAGED_ID_NAME = $(MANAGED_ID_NAME)"
	@echo "  KEY_NAME        = $(KEY_NAME)"
	@echo "  RESOURCE_GROUP  = $(RESOURCE_GROUP)"
	@echo "  KEYVAULT_NAME   = $(KEYVAULT_NAME)"
	@echo "  KEYVAULT_TYPE   = $(KEYVAULT_TYPE)"
	@echo "  TEMPLATE_NAME   = $(TEMPLATE_NAME)"
	@echo "  SUBSCRIPTION_ID = $(SUBSCRIPTION_ID)"
	@echo "  PRINCIPAL_ID    = $(PRINCIPAL_ID)"


# --------------------------------------------------
# Create managed ID and assign role
# --------------------------------------------------
create-managed-id:
	az identity create --name $(MANAGED_ID_NAME) --resource-group $(RESOURCE_GROUP) --location $(REGION)

assign-role:
	@if [ "$(KEYVAULT_TYPE)" = "mhsm" ]; then \
		role="Managed HSM Crypto Service Release User"; \
		vault_par_dir="managedHSMs"; \
	elif [ "$(KEYVAULT_TYPE)" = "akv" ]; then \
		role="Key Vault Crypto Service Release User"; \
		vault_par_dir="vaults"; \
	else \
		echo "KEYVAULT_TYPE must be 'akv' or 'mhsm'"; \
		exit 1; \
	fi; \
	object_id=$$(az identity show --name $(MANAGED_ID_NAME) --resource-group $(RESOURCE_GROUP) --query principalId -o tsv); \
	scope="/subscriptions/$(SUBSCRIPTION_ID)/resourceGroups/$(RESOURCE_GROUP)/providers/Microsoft.KeyVault/$$vault_par_dir/$(KEYVAULT_NAME)"; \
	echo "Assigning role: '$$role' to object ID: '$$object_id'"; \
	az role assignment create --assignee-object-id "$$object_id" --assignee-principal-type "ServicePrincipal" --role "$$role" --scope "$$scope"


# --------------------------------------------------
# Check current subscription ID, managed ID, etc.
# --------------------------------------------------
subscription-id:
	az account show --query id -o tsv

managed-id:
	az identity show --name $(MANAGED_ID_NAME) --resource-group $(RESOURCE_GROUP) --query id -o tsv

principal-id:
	az identity show --name $(MANAGED_ID_NAME) --resource-group $(RESOURCE_GROUP) --query principalId --output tsv

assignments:
	az identity show -g $(RESOURCE_GROUP)


# --------------------------------------------------
# Generate bearer token and policy
# --------------------------------------------------
token:
	@if [ "$(KEYVAULT_TYPE)" = "mhsm" ]; then \
		az account get-access-token --resource "https://managedhsm.azure.net"; \
	elif [ "$(KEYVAULT_TYPE)" = "akv" ]; then \
		az account get-access-token --resource "https://vault.azure.net"; \
	else \
		echo "Usage: make token type 'akv' or 'mhsm' in '.env.mk'"; \
		exit 1; \
	fi

policy:
	az confcom acipolicygen -a $(TEMPLATE_NAME) --debug-mode


# --------------------------------------------------
# Import key into the vault
# --------------------------------------------------
import: 
	go run "../../../tools/importkey/main.go" -c "importkeyconfig.json"


# --------------------------------------------------
# Deploy the ARM template
# --------------------------------------------------
deployment:
	az deployment group create \
		--resource-group $(RESOURCE_GROUP) \
		--template-file $(TEMPLATE_NAME)
