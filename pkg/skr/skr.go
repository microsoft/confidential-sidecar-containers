// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/msi"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ResourceIdManagedHSM = "https%3A%2F%2Fmanagedhsm.azure.net"
	ResourceIdVault      = "https%3A%2F%2Fvault.azure.net"
	ERROR_STRING         = `ERROR: Please refer to the documentation for more information on how to use this sidecar.
ACI: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/skr/aci/README.md
KATA: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/skr/aks/README.md
Troubleshooting: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/skr/TROUBLESHOOTING.md`
)

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
func SecureKeyRelease(identity common.Identity, certState attest.CertState, SKRKeyBlob common.KeyBlob, uvmInformation common.UvmInformation) (_ jwk.Key, err error) {
	logrus.Info("Performing secure key release...")
	logrus.Debugf("Releasing key blob: %v", SKRKeyBlob)

	// Retrieve an MAA token
	var maaToken string

	// Generate an RSA pair that will be used for wrapping material released from a keyvault. MAA
	// expects the public wrapping key to be formatted as a JSON Web Key (JWK).

	// generate rsa key pair
	logrus.Trace("Generating RSA key pair...")
	privateWrappingKey, err := rsa.GenerateKey(rand.Reader, common.RSASize)
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

	var ResourceIDTemplate string

	// If endpoint contains managedhsm, request a token for managedhsm
	// resource; otherwise for a vault
	if ResourceIDTemplate = ResourceIdVault; strings.Contains(SKRKeyBlob.AKV.Endpoint, "managedhsm") {
		ResourceIDTemplate = ResourceIdManagedHSM
		logrus.Infof("Requesting token from %s", ResourceIDTemplate)
	}

	// retrieve an Azure authentication token for authenticating with AKV
	if SKRKeyBlob.AKV.BearerToken == "" {
		ctx, cancel := context.WithTimeout(context.Background(), msi.WorkloadIdentityRquestTokenTimeout)
		defer cancel()
		bearerToken := ""

		if msi.WorkloadIdentityEnabled() {
			logrus.Info("Requesting token for using workload identity.")
			bearerToken, err = msi.GetAccessTokenFromFederatedToken(ctx, ResourceIDTemplate)
			if err != nil {
				return nil, errors.Wrapf(err, "retrieving authentication token using workload identity failed")
			}
		} else {
			// 2. Interact with Azure Key Vault. The REST API of AKV requires
			//     authentication using an Azure authentication token.
			token, err := common.GetToken(ResourceIDTemplate, identity)
			if err != nil {
				return nil, errors.Wrapf(err, "retrieving authentication token failed")
			}
			bearerToken = token.AccessToken
		}
		logrus.Info("Retrieving Azure authentication token...")

		// set the azure authentication token to the AKV instance
		SKRKeyBlob.AKV.BearerToken = bearerToken
	}
	logrus.Debugf("AAD Token: %s ", SKRKeyBlob.AKV.BearerToken)

	// use the MAA token obtained from the AKV's authority to retrieve the key identified by kid. The ReleaseKey
	// operation requires the private wrapping key to unwrap the encrypted key material released from
	// the AKV.
	logrus.Infof("Releasing key %s...", SKRKeyBlob.KID)
	keyBytes, kty, keyOps, err := SKRKeyBlob.AKV.ReleaseKey(maaToken, SKRKeyBlob.KID, privateWrappingKey)
	if err != nil {
		logrus.Debugf("releasing the key %s failed. err: %s", SKRKeyBlob.KID, err.Error())
		return nil, errors.Wrapf(err, "releasing the key %s failed", SKRKeyBlob.KID)
	}

	logrus.Debugf("Key Type: %s Key %v", kty, keyBytes)

	if kty == "oct" || kty == "oct-HSM" {
		logrus.Trace("Encoding OCT key as JWK...")
		jwKey := jwk.NewSymmetricKey()
		if err := jwKey.FromRaw(keyBytes); err != nil {
			return nil, errors.Wrapf(err, "could not encode OCT key as JWK")
		}
		if len(keyOps) > 0 {
			if err := jwKey.Set(jwk.KeyOpsKey, keyOps); err != nil {
				return nil, errors.Wrapf(err, "setting key_ops on JWK failed")
			}
		}
		return jwKey, nil
	} else if kty == "RSA-HSM" || kty == "RSA" {
		logrus.Trace("Parsing RSA key...")
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse RSA key")
		}

		var privateRSAKey *rsa.PrivateKey = key.(*rsa.PrivateKey)

		logrus.Trace("Encoding RSA key as JWK...")
		jwKey := jwk.NewRSAPrivateKey()
		if err := jwKey.FromRaw(privateRSAKey); err != nil {
			return nil, errors.Wrapf(err, "could not encode RSA key as JWK")
		}
		if len(keyOps) > 0 {
			if err := jwKey.Set(jwk.KeyOpsKey, keyOps); err != nil {
				return nil, errors.Wrapf(err, "setting key_ops on JWK failed")
			}
		}
		return jwKey, nil
	} else if kty == "EC-HSM" || kty == "EC" {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "could not parse ECDSA key")
		}

		var privateEcdsaKey *ecdsa.PrivateKey = key.(*ecdsa.PrivateKey)

		jwKey := jwk.NewECDSAPrivateKey()
		if err := jwKey.FromRaw(privateEcdsaKey); err != nil {
			return nil, errors.Wrapf(err, "could not encode ECDSA key as JWK")
		}
		if len(keyOps) > 0 {
			if err := jwKey.Set(jwk.KeyOpsKey, keyOps); err != nil {
				return nil, errors.Wrapf(err, "setting key_ops on JWK failed")
			}
		}
		return jwKey, nil
	} else {
		return nil, errors.Errorf("released key type %v not supported", kty)
	}
}
