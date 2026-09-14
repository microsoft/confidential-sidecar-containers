// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Identity struct {
	ClientId    string `json:"client_id"`
	PrincipalId string `json:"principal_id"`
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
	identityEndpoint = "IDENTITY_ENDPOINT"
	identityHeader   = "IDENTITY_HEADER"
	secretHeaderName = "secret"
)

// GetToken retrieves an authentication token from IMDS which will be used for
// authorizing requests sent to Azure services requiring authorization (e.g.,
// Azure Blob, AKV)
func GetToken(resourceId string, i Identity) (r TokenResponse, err error) {
	tries := 0
	for {
		r, err = _getToken(resourceId, i)
		if err == nil {
			return r, nil
		}
		tries++
		logrus.Errorf("GetToken: attempt %d failed: %v", tries, err)
		if tries < 3 {
			delay := time.Second * time.Duration(tries*tries)
			logrus.Debugf("Retrying after %ds", delay/time.Second)
			time.Sleep(delay)
		} else {
			logrus.Errorf("GetToken failed after %d attempts", tries)
			return r, err
		}
	}
}

func newTokenRequest(resourceId string, identity Identity) (*http.Request, error) {
	endpoint := os.Getenv(identityEndpoint)
	header := os.Getenv(identityHeader)
	useACIEndpoint := endpoint != "" && header != ""

	if !useACIEndpoint {
		endpoint = TokenURITemplate
	} else if identity.PrincipalId == "" {
		return nil, errors.New("identity.principal_id must be provided in the AzureInformation base64 when IDENTITY_ENDPOINT and IDENTITY_HEADER are set (i.e. on Windows)")
	}

	uri, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing managed identity endpoint failed")
	}
	resource, err := url.QueryUnescape(resourceId)
	if err != nil {
		return nil, errors.Wrapf(err, "decoding managed identity resource failed")
	}
	query := uri.Query()
	query.Set("resource", resource)
	if useACIEndpoint {
		query.Set("principalId", identity.PrincipalId)
	} else if identity.ClientId != "" {
		query.Set("client_id", identity.ClientId)
	}
	uri.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "http get request creation failed")
	}
	if useACIEndpoint {
		request.Header.Set(secretHeaderName, header)
	} else {
		request.Header.Set("Metadata", "true")
	}

	return request, nil
}

func _getToken(resourceId string, identity Identity) (r TokenResponse, err error) {
	request, err := newTokenRequest(resourceId, identity)
	if err != nil {
		return r, err
	}

	httpResponse, err := httpClientDoRequest(request)

	if err != nil {
		return r, errors.Wrapf(err, "http get authentication token failed for %s", request.URL.String())
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
