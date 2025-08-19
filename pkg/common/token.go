// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

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
func GetToken(resourceId string, i Identity) (r TokenResponse, err error) {

	// HTTP GET request to authentication token service

	resource_param := "&resource=" + resourceId
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

// Remove the signature from a MAA token, but leaving the information JSON
// intact.
//
// When loglevel is "debug" or higher, we log the received MAA token. To avoid
// leaking them, safely redact the token by removing the signature.
//
// This function also checks that it is indeed a MAA token, and will redact the
// whole string if it is not.
func RedactMAAToken(token string) string {
	// JWT consists of three parts: header, payload, and signature, separated by
	// dots.  We check the issuer in the payload and remove the last part.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "<redacted invalid token: not a JWT>"
	}
	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "<redacted invalid token: failed to decode payload>"
	}
	var payload map[string]interface{}
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		return "<redacted invalid token: failed to unmarshal payload>"
	}
	issuer, ok := payload["iss"].(string)
	if !ok {
		return "<redacted invalid token: invalid issuer>"
	}
	if !strings.HasSuffix(issuer, ".attest.azure.net") {
		return fmt.Sprintf("<redacted token with issuer %s>", issuer)
	}
	return strings.Join([]string{parts[0], parts[1], "***"}, ".")
}
