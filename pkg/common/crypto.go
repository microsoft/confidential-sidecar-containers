// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

// constructJWKFromPrivateKey returns the JWK format of the public key of the RSA key pair
func constructJWKFromPrivateKey(privateWrappingKey *rsa.PrivateKey) (jwk.Key, error) {
	publicWrappingKey := privateWrappingKey.PublicKey

	jwKey := jwk.NewRSAPublicKey()
	err := jwKey.FromRaw(&publicWrappingKey)

	if err != nil {
		return jwKey, errors.Wrapf(err, "creating a json web key from raw public rsa key failed")
	}

	if err = jwk.AssignKeyID(jwKey); err != nil {
		return jwKey, errors.Wrapf(err, "assigning key identifier to jwk failed")
	}

	if err = jwKey.Set("key_ops", "encrypt"); err != nil {
		return jwKey, errors.Wrapf(err, "assigning operations to jwk failed")
	}

	return jwKey, nil
}

// GenerateJWKSet generates a JWK set from an RSA private key
func GenerateJWKSet(privateWrappingKey *rsa.PrivateKey) ([]byte, error) {
	// construct jwk of the public key and return its bytes representation as expected
	jwKey, err := constructJWKFromPrivateKey(privateWrappingKey)
	if err != nil {
		return nil, err
	}

	var jwkSet struct {
		Keys []jwk.Key `json:"keys"`
	}

	jwkSet.Keys = append(jwkSet.Keys, jwKey)
	jwkSetBytes, err := json.Marshal(jwkSet)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling key blob failed")
	}

	return jwkSetBytes, nil
}

// GenerateJWKSetFromPEM generates a JWK set from an RSA private key in PEM format
func GenerateJWKSetFromPEM(privatePEMString string) ([]byte, error) {
	if privateWrappingKey, err := PrivateKeyFromPEM(privatePEMString); err != nil {
		return nil, errors.New("parsing x509 private key pem failed")
	} else {
		return GenerateJWKSet(privateWrappingKey)
	}
}

// PrivateKeyFromPEM generates a private RSA key from PEM string
func PrivateKeyFromPEM(privatePEMString string) (*rsa.PrivateKey, error) {
	// generate privary key from PEM string
	data, _ := pem.Decode([]byte(privatePEMString))
	if privateWrappingKey, err := x509.ParsePKCS1PrivateKey(data.Bytes); err != nil {
		return nil, errors.New("parsing x509 private key pem failed")
	} else {
		return privateWrappingKey, nil
	}
}
