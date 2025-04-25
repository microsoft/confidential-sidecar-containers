// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type Identity struct {
	ClientId string `json:"client_id"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

const (
	TokenURITemplate = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
)

// GetToken retrieves an authentication token which will be used for authorizing
// requests sent to Azure services requiring authorization (e.g., Azure Blob, AKV)
func GetToken(ResourceId string, i Identity) (r TokenResponse, err error) {

	// HTTP GET request to authentication token service

	resource_param := "&resource=" + ResourceId
	client_id_param := ""

	if i.ClientId != "" {
		client_id_param = "&client_id=" + i.ClientId
	}

	uri := TokenURITemplate + resource_param + client_id_param
	httpResponse, err := HTTPGetRequest(uri, true)

	if err != nil {
		return r, errors.Wrapf(err, "http get authentication token failed for %s", uri)
	}

	httpResponseBodyBytes, err := HTTPResponseBody(httpResponse)
	if err != nil {
		return r, errors.Wrapf(err, "pulling http get authentication token response failed")
	}

	// Unmarshall response body into struct
	err = json.Unmarshal(httpResponseBodyBytes, &r)
	if err != nil {
		return r, errors.Wrapf(err, "unmarshalling authentication token response failed")
	}

	return r, nil
}
