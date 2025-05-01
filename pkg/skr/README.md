This package implements the Secure Key Release operation to release a secret previously imported to Azure Key Vault.
It interacts with the local attesation library to fetch an MAA token and then uses the MAA token when interacting with the Azure Key Vault (AKV) service for releasing a secret previously imported to the key vault with a user-defined release policy.
The AKV API expects an authentication token that has proper permissions to the AKV.

