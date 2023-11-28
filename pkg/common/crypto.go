// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func RSAPrivateKeyFromJWK(jwKey *jwk.Key) (*rsa.PrivateKey, error) {
	jwkJSONBytes, err := json.Marshal(jwKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Released key cannot be marshalled into bytes: %v", err)
	}

	var jwkData struct {
		N string `json:"n"`
		E string `json:"e"`
		D string `json:"d"`
		P string `json:"p"`
		Q string `json:"q"`
	}

	if err := json.Unmarshal(jwkJSONBytes, &jwkData); err != nil {
		return nil, errors.Wrapf(err, "Released key is not a RSA private key.")
	}
	n, err := base64.RawURLEncoding.DecodeString(jwkData.N)
	if err != nil {
		return nil, errors.Wrapf(err, "Interpretting jwk key element failed")
	}
	e, err := base64.RawURLEncoding.DecodeString(jwkData.E)
	if err != nil {
		return nil, errors.Wrapf(err, "Interpretting jwk key element failed")
	}
	d, err := base64.RawURLEncoding.DecodeString(jwkData.D)
	if err != nil {
		return nil, errors.Wrapf(err, "Interpretting jwk key element failed")
	}
	p, err := base64.RawURLEncoding.DecodeString(jwkData.P)
	if err != nil {
		return nil, errors.Wrapf(err, "Interpretting jwk key element failed")
	}
	q, err := base64.RawURLEncoding.DecodeString(jwkData.Q)
	if err != nil {
		return nil, errors.Wrapf(err, "Interpretting jwk key element failed")
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		},
		D: new(big.Int).SetBytes(d),
		Primes: []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		},
	}

	return key, nil
}
