// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ResourceIdManagedHSM = "https%3A%2F%2Fmanagedhsm.azure.net"
	ResourceIdVault      = "https%3A%2F%2Fvault.azure.net"
)

// KeyDerivationBlob contains information about the key that needs to be derived
// from a secret that has been released
//
// Safe use of this is to ensure that the secret has enough entropy. Examples
// include RSA private keys.
type KeyDerivationBlob struct {
	Salt  string `json:"salt,omitempty`
	Label string `json:"label,omitemtpy`
}

// KeyBlob contains information about the AKV service that holds the secret
// to be released.
//
// Authority lists the valid MAA that can issue tokens that the AKV service
// will accept. The key imported to this AKV needs to have included the
// authority's endpoint as the authority in the SKR.

type KeyBlob struct {
	KID       string     `json:"kid"`
	KTY       string     `json:"kty,omitempty"`
	KeyOps    []string   `json:"key_ops,omitempty"`
	Authority attest.MAA `json:"authority"`
	AKV       AKV        `json:"akv"`
}

// SecureKeyRelease releases a key identified by the KID and AKV in the keyblob.
//  1. Retrieve an MAA token using the attestation package. This token can be presented to a Azure Key
//     Vault to release a secret.
//  2. Present the MAA token to the AKV for each secret that will be released. The AKV
//     uses the public key presented as runtime-claims in the MAA token to wrap the released secret. This
//     ensures that only the utility VM in posession of the private wrapping key can decrypt the material
//
// The method requires serveral attributes including the uVM infomration, keyblob that contains
// information about the AKV, authority and the key to be released.
//
// The return type is a JWK key
func SecureKeyRelease(identity common.Identity, certState attest.CertState, SKRKeyBlob KeyBlob, uvmInformation common.UvmInformation) (_ jwk.Key, err error) {
	logrus.Info("Performing secure key release...")
	logrus.Debugf("Releasing key blob: %v", SKRKeyBlob)

	// Retrieve an MAA token
	var maaToken string

	// Generate an RSA pair that will be used for wrapping material released from a keyvault. MAA
	// expects the public wrapping key to be formatted as a JSON Web Key (JWK).

	// generate rsa key pair
	logrus.Info("Generating RSA key pair...")
	privateWrappingKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, errors.Wrapf(err, "rsa key pair generation failed")
	}

	// construct the key blob
	logrus.Info("Construct the key blob...")
	jwkSetBytes, err := common.GenerateJWKSet(privateWrappingKey)
	if err != nil {
		return nil, errors.Wrapf(err, "generating key blob failed")
	}

	// Attest
	logrus.Info("Attesting...")
	maaToken, err = certState.Attest(SKRKeyBlob.Authority, jwkSetBytes, uvmInformation)
	if err != nil {
		return nil, errors.Wrapf(err, "attestation failed")
	}

	// 2. Interact with Azure Key Vault. The REST API of AKV requires
	//     authentication using an Azure authentication token.

	// retrieve an Azure authentication token for authenticating with AKV
	if SKRKeyBlob.AKV.BearerToken == "" {
		logrus.Info("Retrieving Azure authentication token...")
		var ResourceIDTemplate string
		// If endpoint contains managedhsm, request a token for managedhsm
		// resource; otherwise for a vault
		if strings.Contains(SKRKeyBlob.AKV.Endpoint, "managedhsm") {
			logrus.Info("Requesting token for managedhsm...")
			ResourceIDTemplate = ResourceIdManagedHSM
		} else {
			logrus.Info("Requesting token for vault...")
			ResourceIDTemplate = ResourceIdVault
		}

		token, err := common.GetToken(ResourceIDTemplate, identity)
		if err != nil {
			return nil, errors.Wrapf(err, "retrieving authentication token failed")
		}

		// set the azure authentication token to the AKV instance
		SKRKeyBlob.AKV.BearerToken = token.AccessToken
	}
	logrus.Debugf("AAD Token: %s ", SKRKeyBlob.AKV.BearerToken)

	// use the MAA token obtained from the AKV's authority to retrieve the key identified by kid. The ReleaseKey
	// operation requires the private wrapping key to unwrap the encrypted key material released from
	// the AKV.
	logrus.Infof("Releasing key %s...", SKRKeyBlob.KID)
	keyBytes, kty, err := SKRKeyBlob.AKV.ReleaseKey(maaToken, SKRKeyBlob.KID, privateWrappingKey)
	if err != nil {
		logrus.Debugf("releasing the key %s failed. err: %s", SKRKeyBlob.KID, err.Error())
		return nil, errors.Wrapf(err, "releasing the key %s failed", SKRKeyBlob.KID)
	}

	logrus.Debugf("Key Type: %s Key %v", kty, keyBytes)

	if kty == "oct" || kty == "oct-HSM" {
		logrus.Info("Encoding OCT key as JWK...")
		jwKey := jwk.NewSymmetricKey()
		err := jwKey.FromRaw(keyBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "could not encode OCT key as JWK")
		}
		return jwKey, nil
	} else if kty == "RSA-HSM" || kty == "RSA" {
		logrus.Info("Parsing RSA key...")
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse RSA key")
		}

		var privateRSAKey *rsa.PrivateKey = key.(*rsa.PrivateKey)

		logrus.Info("Encoding RSA key as JWK...")
		jwKey := jwk.NewRSAPrivateKey()
		err = jwKey.FromRaw(privateRSAKey)
		if err != nil {
			return nil, errors.Wrapf(err, "could not encode RSA key as JWK")
		}
		return jwKey, nil
	} else {
		return nil, errors.Wrapf(err, "released key type not supported")
	}
}
