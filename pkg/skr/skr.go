// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	ResourceIdManagedHSM = "https%3A%2F%2Fmanagedhsm.azure.net"
)

// KeyBlob contains information about the managed hsm service that holds the secret
// to be released.
//
// Authority lists the valid MAA that can issue tokens that the managed hsm service
// will accept. The key imported to this managed hsm needs to have included the
// authority's endpoint as the authority in the SKR.
type KeyBlob struct {
	KID       string     `json:"kid"`
	Authority attest.MAA `json:"authority"`
	MHSM      MHSM       `json:"mhsm"`
}

// SecureKeyRelease releases a secret identified by the KID and MHSM in the keyblob
// 1. Retrieve an MAA token using the attestation package. This token can be presented to a Azure Key
//    Vault managed HSM to release a secret.
// 2. Present the MAA token to the managed HSM for each secret that will be released. The managed HSM
//    uses the public key presented as runtime-claims in the MAA token to wrap the released secret. This
//    ensures that only the utility VM in posession of the private wrapping key can decrypt the material
//
// The method requires serveral attributes including the security policy, the keyblob that contains
// information about the mhsm, authority and the key to be released.
//
// TO-DO: The if fetchSNPReportFlag codebase will be removed when pushed to public repo. It is here to
// allow testing on non-snp hw with fixed attestation reports.
func SecureKeyRelease(EncodedSecurityPolicy string, certCache attest.CertCache, identity common.Identity, SKRKeyBlob KeyBlob) (_ []byte, err error) {

	logrus.Debugf("Releasing key blob: %v", SKRKeyBlob)

	// Retrieve an MAA token

	var maaToken string

	// Generate an RSA pair that will be used for wrapping material released from a keyvault. MAA
	// expects the public wrapping key to be formatted as a JSON Web Key (JWK).

	// generate rsa key pair
	privateWrappingKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, errors.Wrapf(err, "rsa key pair generation failed")
	}

	// construct the key blob
	jwkSetBytes, err := common.GenerateJWKSet(privateWrappingKey)
	if err != nil {
		return nil, errors.Wrapf(err, "generating key blob failed")
	}

	// base64 decode the incoming encoded security policy
	if EncodedSecurityPolicy == "" {
		maaToken, err = attest.Attest(certCache, SKRKeyBlob.Authority, nil, jwkSetBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "attestation failed")
		}
	} else {
		policyBlobBytes, err := base64.StdEncoding.DecodeString(EncodedSecurityPolicy)
		if err != nil {
			return nil, errors.Wrap(err, "decoding policy from Base64 format failed")
		}

		// Attest
		maaToken, err = attest.Attest(certCache, SKRKeyBlob.Authority, policyBlobBytes, jwkSetBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "attestation failed")
		}
	}

	// 2. Interact with Azure Key Vault managed HSM. The REST API of AKV managed HSM
	// requires authentication using an Azure authentication token.

	// retrieve an Azure authentication token for authenticating with managed hsm
	if SKRKeyBlob.MHSM.BearerToken == "" {
		token, err := common.GetToken(ResourceIdManagedHSM, identity)
		if err != nil {
			return nil, errors.Wrapf(err, "retrieving authentication token failed")
		}

		// set the azure authentication token to the MHSM instance
		SKRKeyBlob.MHSM.BearerToken = token.AccessToken
		logrus.Debugf("AAD Token: %s ", token.AccessToken)
	}

	// use the MAA token obtained from the mhsm's authority to retrieve the key identified by kid. The ReleaseKey
	// operation requires the private wrapping key to unwrap the encrypted key material released from
	// the managed HSM.
	key, err := SKRKeyBlob.MHSM.ReleaseKey(maaToken, SKRKeyBlob.KID, privateWrappingKey)
	logrus.Debugf("Releasing key: %v %s", key, err)
	if err != nil {
		return nil, errors.Wrapf(err, "releasing the key %s failed", SKRKeyBlob.KID)
	}

	return key, nil
}
