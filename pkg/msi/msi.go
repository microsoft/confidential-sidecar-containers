package msi

import (
	"context"
	"fmt"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Convert federated token stored in a file into access token for a resource
// Borrowed from https://github.com/Azure/azure-workload-identity/blob/c155ecee0d9fa681c15ead4bbdce729fd8c99da1/pkg/proxy/proxy.go#L195
// See tutorial at: https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity

func GetAccessTokenFromFederatedToken(ctx context.Context, federatedTokenFile, clientID, tenantID, resource string) (string, error) {
	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		token, err := os.ReadFile(federatedTokenFile)
		return string(token), err
	})

	confidentialClient, err := confidential.New(clientID, cred,
		confidential.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)))
	if err != nil {
		return "", fmt.Errorf("failed to create confidential client: %v", err)
	}

	result, err := confidentialClient.AcquireTokenByCredential(ctx, []string{resource + "/.default"})
	if err != nil {
		return "", fmt.Errorf("failed to acquire access token: %v", err)
	}
	return result.AccessToken, nil
}
