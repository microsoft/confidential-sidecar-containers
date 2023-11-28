package common

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestRSAPrivateKeyFromJWK(t *testing.T) {
	// Mock JWK key data
	jwkData := struct {
		KTY string `json:"kty"`
		KID string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
		D   string `json:"d"`
		P   string `json:"p"`
		Q   string `json:"q"`
	}{
		KTY: "RSA",
		KID: "test-key1",
		N:   base64.RawURLEncoding.EncodeToString([]byte("mockN")),
		E:   base64.RawURLEncoding.EncodeToString([]byte("mockE")),
		D:   base64.RawURLEncoding.EncodeToString([]byte("mockD")),
		P:   base64.RawURLEncoding.EncodeToString([]byte("mockP")),
		Q:   base64.RawURLEncoding.EncodeToString([]byte("mockQ")),
	}

	// Convert JWK data to JSON
	jwkJSONBytes, err := json.Marshal(jwkData)
	assert.NoError(t, err, "Failed to marshall JWK key")

	jwkKeySet, err := jwk.Parse([]byte(jwkJSONBytes))
	assert.NoError(t, err, "Failed to parse JWK key JSON")

	jwkKey, found := jwkKeySet.LookupKeyID("test-key1")
	assert.True(t, found, "Failed to find test-key1")

	// Call the function being tested
	rsaPrivateKey, err := RSAPrivateKeyFromJWK(&jwkKey)
	assert.NoError(t, err, "Failed to convert RSA private key from JWK key")

	expectedN := new(big.Int).SetBytes([]byte("mockN"))
	expectedE := int(new(big.Int).SetBytes([]byte("mockE")).Int64())
	expectedD := new(big.Int).SetBytes([]byte("mockD"))
	expectedP := new(big.Int).SetBytes([]byte("mockP"))
	expectedQ := new(big.Int).SetBytes([]byte("mockQ"))

	assert.Equal(t, expectedN, rsaPrivateKey.PublicKey.N, "Mismatch in public key N value")
	assert.Equal(t, expectedE, rsaPrivateKey.PublicKey.E, "Mismatch in public key E value")
	assert.Equal(t, expectedD, rsaPrivateKey.D, "Mismatch in private key D value")
	assert.Equal(t, expectedP, rsaPrivateKey.Primes[0], "Mismatch in private key P value")
	assert.Equal(t, expectedQ, rsaPrivateKey.Primes[1], "Mismatch in private key Q value")
}
