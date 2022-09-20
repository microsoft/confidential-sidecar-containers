// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"runtime"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/microsoft/confidential-sidecars/pkg/common"
	"github.com/pkg/errors"
)

const (
	MHSMImportKeyRequestURITemplate  = "https://%s/keys/%s?%s"
	MHSMReleaseKeyRequestURITemplate = "https://%s/keys/%s/release?%s"
	// We use 2048-bit RSA cryptography
	RSASize = 2048
)

type MHSM struct {
	Endpoint    string `json:"endpoint"`
	APIVersion  string `json:"api_version,omitempty"`
	BearerToken string `json:"bearer_token,omitempty"`
}

// Helper Functions

// rsaAESKeyUnwrap unwraps a key using the RSA_AES algorithm
func rsaAESKeyUnwrap(alg string, ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	// Ciphertext data format
	// ======================
	// First N bytes contain the encrypted emphimeral AES key where N equals the
	// size of the private key. Remaining bytes are the wrapped key
	encryptedKEK := make([]byte, RSASize/8)
	for i := range encryptedKEK {
		encryptedKEK[i] = ciphertext[i]
	}

	encryptedKey := make([]byte, len(ciphertext)-RSASize/8)
	for i := range encryptedKey {
		encryptedKey[i] = ciphertext[i+RSASize/8]
	}

	// Before performing decryption, choose the hash function based on the key
	// encryption algorithm
	var hash hash.Hash

	if alg == "CKM_RSA_AES_KEY_WRAP" {
		// CKM_RSA_AES_KEY_WRAP relies on SHA1 hash
		hash = sha1.New()
	} else if alg == "RSA_AES_KEY_WRAP_256" {
		// RSA_AES_KEY_WRAP_256 relies on SHA256 hash
		hash = sha256.New()
	} else if alg == "RSA_AES_KEY_WRAP_384" {
		// RSA_AES_KEY_WRAP_384 relies on SHA384 hash
		hash = sha512.New384()
	} else {
		return nil, errors.New("Unsupported hash for the wrapping protocol")
	}

	kek, err := rsa.DecryptOAEP(hash, rand.Reader, priv, encryptedKEK, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "OAEP decryption failed")
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errors.Wrapf(err, "new aes cipher generation failed")
	}

	return aesUnwrapPadding(cipher, encryptedKey)
}

// JWS and x509 helper functions
type jwsHeader struct {
	Alg string   `json:"alg"`
	KID string   `json:"kid"`
	X5C []string `json:"x5c"`
	SIG string   `json:"x5t#S256"`
}

// verifyJWSTokenconfirms that the JWS token is valid comprising three fields:
// header, payload, signature
func verifyJWSToken(token string) error {
	var tokenParts = strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return errors.Errorf("jws token validation failed")
	}
	return nil
}

// extractJWSTokenHeader extracts the header of a JWS token
func (header *jwsHeader) extractJWSTokenHeader(token string) error {
	headerString := strings.Split(token, ".")[0]
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerString) // M-HSM uses no-padding base64 url
	if err != nil {
		return errors.Wrapf(err, "decoding header failed")
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return errors.Wrapf(err, "unmarshalling header failed")
	}
	return nil
}

// validateJWSToken validates a JWS token using the key and alg attributes
func validateJWSToken(token string, key interface{}, alg jwa.SignatureAlgorithm) ([]byte, error) {
	payloadString, err := jws.Verify([]byte(token), alg, key)
	if err != nil {
		return nil, errors.Wrapf(err, "jws token verification failed")
	}
	return []byte(payloadString), nil
}

// parseX509Certificate parses a x509 certificate from a string
func parseX509Certificate(certstring string) (*x509.Certificate, error) {
	certBytes, err := base64.StdEncoding.DecodeString(certstring)
	if err != nil {
		return nil, errors.Wrapf(err, "decoding certificate from string failed")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing certificate failed")
	}

	return cert, err
}

// verifyX509CertChain verifies a cert chain against a trusted root cert pool and
// a trusted server for the leaf's certificate
func verifyX509CertChain(dnsName string, certChain []string, roots *x509.CertPool) error {
	// we construct an intermediate cert pool using the intermediate certs in the
	// chain excluding the root certificate and the leaf certificate
	cert, err := parseX509Certificate(certChain[0])
	if err != nil {
		return errors.Wrapf(err, "verification of leaf's certificate chain failed while parsing X5C[0]")
	}

	intermediates := x509.NewCertPool()
	for index := len(certChain) - 2; index > 0; index-- {
		certificate, err := parseX509Certificate(certChain[index])
		if err != nil {
			return errors.Wrapf(err, "verification of leaf's certificate chain failed while parsing X5C[%d]", index)
		}

		intermediates.AddCert(certificate)
	}

	// We ensure that the server protected by the leaf certificate matches
	// the managed hsm's endpoint
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: dnsName, Roots: roots, Intermediates: intermediates}); err != nil {
		return errors.Wrapf(err, "verification of leaf's certificate chain failed")
	}

	return nil
}

// MHSM class
type OctKey struct {
	KTY     string   `json:"kty"`
	KeyOps  []string `json:"key_ops"`
	K       string   `json:"k"`
	KeySize int      `json:"key_size"`
}

// ImportKey SKR interface
type importKeyAttributes struct {
	Exportable bool `json:"exportable"`
}

type importKeyReleasePolicy struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"`
}

type importKeyRequest struct {
	Key           interface{}            `json:"key"`
	Attributes    importKeyAttributes    `json:"attributes"`
	ReleasePolicy importKeyReleasePolicy `json:"release_policy"`
}

type ImportKeyResponseKey struct {
	KTY           string      `json:"kty"`
	KeyOps        []string    `json:"key_ops"`
	KID           string      `json:"kid"`
	ReleasePolicy interface{} `json:"release_policy"`
}

type ImportKeyResponse struct {
	Attributes interface{}          `json:"attributes"`
	Key        ImportKeyResponseKey `json:"key"`
}

// SKR releasy policy struct
type ClaimStruct struct {
	Claim  string `json:"claim"`
	Equals string `json:"equals"`
}

type OuterClaimStruct struct {
	Authority string        `json:"authority"`
	AllOf     []ClaimStruct `json:"allOf"`
}

type ReleasePolicy struct {
	Version string             `json:"version"`
	AnyOf   []OuterClaimStruct `json:"anyOf"`
}

// ReleaseKey interface
type releaseKeyRequest struct {
	Target string `json:"target"`
}

type releaseKeyResponse struct {
	Value string `json:"value"`
}

type releaseKeyResponseJWSPayload struct {
	Request  releaseKeyResponseJWSPayloadRequest  `json:"request"`
	Response releaseKeyResponseJWSPayloadResponse `json:"response"`
}

type releaseKeyResponseJWSPayloadRequest struct {
	APIVersion string `json:"api-version"`
	Enc        string `json:"enc"`
	KID        string `json:"kid"`
}

type releaseKeyResponseJWSPayloadResponse struct {
	Key ReleaseKeyResponseKey `json:"key"`
}

type ReleaseKeyResponseKey struct {
	Attributes    interface{}             `json:"attributes"`
	Key           ReleaseKeyEncryptedKey  `json:"key"`
	ReleasePolicy ReleaseKeyReleasePolicy `json:"release_policy"`
}

type releaseKeyKeyHSM struct {
	// Ciphertext is the ciphertext of the released key material. It has been
	// generated based on the ReleaseKeyResponseJWSPayloadRequest.Enc algorithm
	Ciphertext    string      `json:"ciphertext"`
	Header        interface{} `json:"header"`
	SchemaVersion string      `json:"schema_version"`
}

type ReleaseKeyEncryptedKey struct {
	// KeyHSM is base64 representation of the releaseKeyKeyHSM structure
	KeyHSM string   `json:"key_hsm"`
	KID    string   `json:"kid"`
	KTY    string   `json:"kty"`
	KeyOps []string `json:"key_ops"`
}

type ReleaseKeyReleasePolicy struct {
	ContentType string `json:"contentType"`
	Data        string `json:"data"`
}

// ImportPlaintextKey imports a plaintext key to a keyvault. The key is associated
// with a release policy
func (mHSM MHSM) ImportPlaintextKey(key interface{}, releasePolicy ReleasePolicy, keyName string) (mHSMResponse *ImportKeyResponse, err error) {
	// create import key request
	releasePolicyBytes, err := json.Marshal(releasePolicy)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling release policy failed")
	}

	request := importKeyRequest{
		Key: key,
		Attributes: importKeyAttributes{
			Exportable: true,
		},
		ReleasePolicy: importKeyReleasePolicy{
			ContentType: "application/json; version=1.0",
			// M-HSM uses no-padding base64 url
			Data: base64.RawURLEncoding.EncodeToString(releasePolicyBytes),
		},
	}

	importKeyJSON, err := json.Marshal(request)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling import key request failed")
	}

	// Create HTTP request for managed HSM
	uri := fmt.Sprintf(MHSMImportKeyRequestURITemplate, mHSM.Endpoint, keyName, mHSM.APIVersion)
	httpResponse, err := common.HTTPPRequest("PUT", uri, importKeyJSON, mHSM.BearerToken)
	if err != nil {
		return nil, errors.Wrapf(err, "mhsm put request failed")
	}

	httpResponseBodyBytes, err := common.HTTPResponseBody(httpResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "pulling mhsm response body failed")
	}

	mHSMResponse = new(ImportKeyResponse)
	if err = json.Unmarshal(httpResponseBodyBytes, mHSMResponse); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling http response to importkey response failed")
	}

	return mHSMResponse, nil
}

// ReleaseKey releases a key from a key vault. It takes as attributes the MAA token, the
// identifier of the key to be released and the private key of the wrapping RSA key pair
// that has been used by the managed HSM to wrap the released secret. Recall that the MAA
// token contains the public key of the wrapping RSA key pair as a runtime claim. The
// managed HSM uses the key to wrap released secrets if the claims in the MAA token satisfy
// the release policy. ReleaseKey uses the private key to locally unwrap the released secrets.
// The private key is kept within the utility VM and hence is isolated with hardware-based
// guarantees.
func (mHSM MHSM) ReleaseKey(maaTokenBase64 string, kid string, privateWrappingKey *rsa.PrivateKey) (_ []byte, err error) {
	// Construct release key request to managed HSM
	request := releaseKeyRequest{
		Target: maaTokenBase64,
	}
	// Create HTTP POST request to a managed HSM service that requires authorization
	// bearer token
	releaseKeyJSONData, err := json.Marshal(request)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling release key request failed")
	}

	uri := fmt.Sprintf(MHSMReleaseKeyRequestURITemplate, mHSM.Endpoint, kid, mHSM.APIVersion)

	httpResponse, err := common.HTTPPRequest("POST", uri, releaseKeyJSONData, mHSM.BearerToken)
	if err != nil {
		return nil, errors.Wrapf(err, "mhsm post request failed")
	}

	httpResponseBodyBytes, err := common.HTTPResponseBody(httpResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "pulling mhsm response body failed")
	}

	// Extract the value field found in the response
	mHSMResponse := new(releaseKeyResponse)
	if err = json.Unmarshal(httpResponseBodyBytes, mHSMResponse); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling http response to releasekey response failed")
	}

	return _releaseKey(mHSM, mHSMResponse.Value, privateWrappingKey)
}

// _releaseKey verifies and validates that the JWS the mHSM is a genuine one before decrypting
// the encrypted key encapsulated in the JWS object
// (1) Verify that it is a well formed JWS object
// (2) Use the thumbprint or first entry in the chain to obtain the public key of the signer
// (3) Verify the signature of the JWS object
// (4) Verify the identity of the signer
// (5) Verify the certificate chain for the signer
// (6) Ensure that the root of the certificate chain is trusted
// (7) Unwrap the wrapped key from the payload
func _releaseKey(mHSM MHSM, mHSMJWS string, privateWrappingKey *rsa.PrivateKey) (key []byte, err error) {
	// (1) Verify that it is a well formed JWS object
	if err := verifyJWSToken(mHSMJWS); err != nil {
		return nil, err
	}

	// (2) Use the thumbprint or first entry in the chain to obtain the public key of the signer
	var header jwsHeader
	if err := header.extractJWSTokenHeader(mHSMJWS); err != nil {
		return nil, err
	}

	leafCertificate, err := parseX509Certificate(header.X5C[0])
	if err != nil {
		return nil, errors.Wrapf(err, "parsing certificate X5C[0] failed")
	}

	leafKey, ok := leafCertificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Wrapf(err, "could not cast interface to rsa.PublicKey")
	}

	// (3) Signature validation of the JWS token
	payloadBytes, err := validateJWSToken(mHSMJWS, leafKey, jwa.SignatureAlgorithm(header.Alg))
	if err != nil {
		return nil, err
	}

	// (4) (5) and (6) Verify the leaf certificate using a cert chain that is rooted to the the system's cert pool
	// windows does not have a system cert pool. for now we use the root certificate in the returned chain

	// TO-DO for WCOW we will need to check the cert against the trusted pool of root CAs.
	var roots *x509.CertPool

	if runtime.GOOS == "windows" {
		roots = x509.NewCertPool()

		rootCertificate, err := parseX509Certificate(header.X5C[len(header.X5C)-1])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse root certificate X5C[%d]", len(header.X5C)-1)
		}

		roots.AddCert(rootCertificate)
	} else {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrapf(err, "could not generate a system cert pool")
		}
	}

	if err := verifyX509CertChain(mHSM.Endpoint, header.X5C, roots); err != nil {
		return nil, err
	}

	// (7) Unwrap the wrapped key from the signed payload
	var payloadJSON releaseKeyResponseJWSPayload
	if err := json.Unmarshal(payloadBytes, &payloadJSON); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling jws response payload failed")
	}

	// decode KeyHSM no-padding base64 url representation and retrieve the Ciphertext field
	keyHSMBytes, err := base64.RawURLEncoding.DecodeString(payloadJSON.Response.Key.Key.KeyHSM)
	if err != nil {
		return nil, errors.Wrapf(err, "decoding keyHSM failed")
	}

	var keyHSMJson releaseKeyKeyHSM
	if err := json.Unmarshal(keyHSMBytes, &keyHSMJson); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling keyHSM failed")
	}

	// decode Ciphertext no-padding base64 url representation and wnwrap the key
	ciphertext, err := base64.RawURLEncoding.DecodeString(keyHSMJson.Ciphertext)
	if err != nil {
		return nil, errors.Wrapf(err, "decoding keyHSM's ciphertext failed")
	}

	key, err = rsaAESKeyUnwrap(payloadJSON.Request.Enc, ciphertext, privateWrappingKey)
	if err != nil {
		return nil, errors.Wrapf(err, "aes key unwrap failed")
	}

	return key, nil
}
