package msi

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

const (
	AZURE_CLIENT_ID                    = "AZURE_CLIENT_ID"
	AZURE_TENANT_ID                    = "AZURE_TENANT_ID"
	AZURE_FEDERATED_TOKEN_FILE         = "AZURE_FEDERATED_TOKEN_FILE"
	WorkloadIdentityRquestTokenTimeout = time.Second * 7
)

// Convert federated token stored in a file into access token for a resource
// Borrowed from https://github.com/Azure/azure-workload-identity/blob/c155ecee0d9fa681c15ead4bbdce729fd8c99da1/pkg/proxy/proxy.go#L195
// See tutorial at: https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity

func GetAccessTokenFromFederatedToken(ctx context.Context, encodedResourceUrl string) (string, error) {
	clientID := os.Getenv(AZURE_CLIENT_ID)
	tenantID := os.Getenv(AZURE_TENANT_ID)
	tokenFile := os.Getenv(AZURE_FEDERATED_TOKEN_FILE)

	decodedURL, err := url.QueryUnescape(encodedResourceUrl)
	if err != nil {
		return "", fmt.Errorf("failed to decode resource url: %v", err)
	}

	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		token, err := os.ReadFile(tokenFile)
		return string(token), err
	})

	confidentialClient, err := confidential.New(fmt.Sprintf("https://login.microsoftonline.com/%s", tenantID), clientID, cred)
	if err != nil {
		return "", fmt.Errorf("failed to create confidential client: %v", err)
	}

	result, err := confidentialClient.AcquireTokenByCredential(ctx, []string{decodedURL + "/.default"})
	if err != nil {
		return "", fmt.Errorf("failed to acquire access token: %v", err)
	}
	return result.AccessToken, nil
}

func WorkloadIdentityEnabled() bool {
	clientID := os.Getenv(AZURE_CLIENT_ID)
	tenantID := os.Getenv(AZURE_TENANT_ID)
	tokenFile := os.Getenv(AZURE_FEDERATED_TOKEN_FILE)
	return clientID != "" && tenantID != "" && tokenFile != ""
}
