// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

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
	KID       string   `json:"kid"`
	KTY       string   `json:"kty,omitempty"`
	KeyOps    []string `json:"key_ops,omitempty"`
	Authority MAA      `json:"authority"`
	AKV       AKV      `json:"akv"`
}
