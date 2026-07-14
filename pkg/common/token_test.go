package common

import (
	"net/url"
	"testing"
)

func TestNewTokenRequest(t *testing.T) {
	testCases := []struct {
		name             string
		endpoint         string
		header           string
		identity         Identity
		expectedHost     string
		expectedQuery    url.Values
		expectedMetadata string
		expectedSecret   string
		expectError      bool
	}{
		{
			name:         "system-assigned identity via IMDS",
			expectedHost: "169.254.169.254",
			expectedQuery: url.Values{
				"api-version": {"2018-02-01"},
				"resource":    {"https://vault.azure.net"},
			},
			expectedMetadata: "true",
		},
		{
			name:         "user-assigned identity via IMDS",
			identity:     Identity{ClientId: "client-id"},
			expectedHost: "169.254.169.254",
			expectedQuery: url.Values{
				"api-version": {"2018-02-01"},
				"client_id":   {"client-id"},
				"resource":    {"https://vault.azure.net"},
			},
			expectedMetadata: "true",
		},
		{
			name:         "Windows ACI identity endpoint",
			endpoint:     "http://10.0.0.1/token?api-version=2021-02-01",
			header:       "header-secret",
			identity:     Identity{ClientId: "ignored-client-id", PrincipalId: "principal-id"},
			expectedHost: "10.0.0.1",
			expectedQuery: url.Values{
				"api-version": {"2021-02-01"},
				"principalId": {"principal-id"},
				"resource":    {"https://vault.azure.net"},
			},
			expectedSecret: "header-secret",
		},
		{
			name:             "incomplete ACI environment falls back to IMDS",
			endpoint:         "http://10.0.0.1/token",
			identity:         Identity{ClientId: "client-id"},
			expectedHost:     "169.254.169.254",
			expectedMetadata: "true",
			expectedQuery: url.Values{
				"api-version": {"2018-02-01"},
				"client_id":   {"client-id"},
				"resource":    {"https://vault.azure.net"},
			},
		},
		{
			name:        "Windows ACI requires principal ID",
			endpoint:    "http://10.0.0.1/token",
			header:      "header-secret",
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv(identityEndpoint, testCase.endpoint)
			t.Setenv(identityHeader, testCase.header)

			request, err := newTokenRequest("https://vault.azure.net", testCase.identity)
			if testCase.expectError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("did not expect an error: %v", err)
			}
			if request.URL.Host != testCase.expectedHost {
				t.Errorf("expected host %q, got %q", testCase.expectedHost, request.URL.Host)
			}
			if request.URL.Query().Encode() != testCase.expectedQuery.Encode() {
				t.Errorf("expected query %q, got %q", testCase.expectedQuery.Encode(), request.URL.Query().Encode())
			}
			if actual := request.Header.Get("Metadata"); actual != testCase.expectedMetadata {
				t.Errorf("expected Metadata header %q, got %q", testCase.expectedMetadata, actual)
			}
			if actual := request.Header.Get(secretHeaderName); actual != testCase.expectedSecret {
				t.Errorf("expected secret header %q, got %q", testCase.expectedSecret, actual)
			}
		})
	}
}

func Test_RedactMAAToken(t *testing.T) {
	th := "e30."
	testCases := [][2]string{
		{th + "eyJpc3MiOiAiaHR0cHM6Ly9zaGFyZWRjbGMuY2xjLmF0dGVzdC5henVyZS5uZXQifQ.AAAA", th + "eyJpc3MiOiAiaHR0cHM6Ly9zaGFyZWRjbGMuY2xjLmF0dGVzdC5henVyZS5uZXQifQ.***"},
		{"invalid", "<redacted invalid token: not a JWT>"},
		{th + "eyJpc3MiOiAiaHR0cHM6Ly9zdHMubWljcm9zb2Z0LmNvbSJ9.AAAA", "<redacted token with issuer https://sts.microsoft.com>"},
	}

	for _, tc := range testCases {
		input, expected := tc[0], tc[1]
		actual := RedactMAAToken(input)
		if actual != expected {
			t.Errorf("Expected RedactToken(%q) to be %q, got %q", input, expected, actual)
		}
	}
}
