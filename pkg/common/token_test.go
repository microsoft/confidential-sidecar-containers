package common

import "testing"

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
