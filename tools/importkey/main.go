// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/lestrrat-go/jwx/jwk"
)

type importKeyConfig struct {
	KeyDerivation skr.KeyDerivationBlob `json:"key_derivation,omitempty"`
	Key           skr.KeyBlob           `json:"key"`
	Claims        [][]skr.ClaimStruct   `json:"claims"`
	Identity      common.Identity       `json:"identity,omitempty"`
}

type RSAKey struct {
	KTY    string   `json:"kty"`
	KeyOps []string `json:"key_ops"`
	D      string   `json:"d"`
	DP     string   `json:"dp"`
	DQ     string   `json:"dq"`
	E      string   `json:"e"`
	N      string   `json:"n"`
	P      string   `json:"p"`
	Q      string   `json:"q"`
	QI     string   `json:"qi"`
}

type OctKey struct {
	KTY     string   `json:"kty"`
	KeyOps  []string `json:"key_ops,omitempty"`
	K       string   `json:"k"`
	KeySize int      `json:"key_size"`
}

func main() {
	// variables declaration
	var configFile string
	var keyHexString string
	var keyRSAPEMFile string
	var runInsideAzure bool
	var outputOctetKeyfile bool

	// flags declaration using flag package
	flag.StringVar(&configFile, "c", "", "Specify config file to process")
	flag.StringVar(&keyHexString, "kh", "", "Specify oct key bytes in hexstring [optional]")
	flag.StringVar(&keyRSAPEMFile, "kp", "", "Specify path to RSA key PEM file [optional]")
	flag.BoolVar(&runInsideAzure, "a", false, "Run within Azure VM [optional]")
	flag.BoolVar(&outputOctetKeyfile, "out", false, "Output octet key binary file")
	flag.Parse() // after declaring flags we need to call it

	flag.Parse()
	if flag.NArg() != 0 || len(configFile) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	importKeyCfg := new(importKeyConfig)
	if configBytes, err := ioutil.ReadFile(configFile); err != nil {
		fmt.Println("Error reading Azure services configuration")
		os.Exit(1)
	} else if err = json.Unmarshal(configBytes, importKeyCfg); err != nil {
		fmt.Println("Error unmarshalling import key configuration " + string(configBytes))
		os.Exit(1)
	}

	// retrieve a token from AKV. this requires to be run within a VM that has been assigned a managed identity associated with the AKV resource
	if runInsideAzure {
		var ResourceIDTemplate string
		if strings.Contains(importKeyCfg.Key.AKV.Endpoint, "managedhsm") {
			ResourceIDTemplate = "https%3A%2F%2Fmanagedhsm.azure.net"
		} else {
			ResourceIDTemplate = "https%3A%2F%2Fvault.azure.net"
		}

		token, err := common.GetToken(ResourceIDTemplate, importKeyCfg.Identity)
		if err != nil {
			fmt.Println("Error retrieving the authentication token")
			os.Exit(1)
		}

		importKeyCfg.Key.AKV.BearerToken = token.AccessToken
	}

	// create release policy
	var releasePolicy skr.ReleasePolicy

	releasePolicy.Version = "1.0.0"

	for _, allOfStatement := range importKeyCfg.Claims {
		// authority denotes authorized MAA endpoint that can present MAA tokens to the AKV
		releasePolicy.AnyOf = append(
			releasePolicy.AnyOf,
			skr.OuterClaimStruct{
				Authority: "https://" + importKeyCfg.Key.Authority.Endpoint,
				AllOf:     allOfStatement,
			},
		)
	}

	var key interface{}
	var octKey []byte

	if importKeyCfg.Key.KTY == "RSA-HSM" {
		var jwKey jwk.RSAPrivateKey
		if keyRSAPEMFile == "" {
			privateRSAKey, err := rsa.GenerateKey(rand.Reader, skr.RSASize)
			if err != nil {
				fmt.Println(err)
				return
			}

			privateRSAKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateRSAKey)
			if err != nil {
				fmt.Println(err)
				return
			}

			var privateRSAKeyBlock = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privateRSAKeyBytes,
			}

			privateRSAKeyFile, err := os.OpenFile("private_key.pem", os.O_WRONLY|os.O_CREATE, 0644)
			if err != nil {
				fmt.Println(err)
				return
			}

			err = pem.Encode(privateRSAKeyFile, privateRSAKeyBlock)
			if err != nil {
				fmt.Println(err)
				return
			}

			privateRSAKeyFile.Close()

			// convert to JSON Web Key (JWK) format
			jwKey = jwk.NewRSAPrivateKey()
			err = jwKey.FromRaw(privateRSAKey)

			if err != nil {
				fmt.Println(err)
				return
			}

			// note that if KeyOps is nil, the HSM will whitelist all operations
			jwKey.Set("key_ops", importKeyCfg.Key.KeyOps)
			key = jwKey
		} else {

			privateRSAKeyBytes, err := ioutil.ReadFile(keyRSAPEMFile)
			if err != nil {
				fmt.Println(err)
				return
			}

			data, _ := pem.Decode(privateRSAKeyBytes)
			privateKey, err := x509.ParsePKCS8PrivateKey(data.Bytes)
			if err != nil {
				fmt.Println(err)
				return
			}

			// convert to JSON Web Key (JWK) format
			jwKey = jwk.NewRSAPrivateKey()
			err = jwKey.FromRaw(privateKey.(*rsa.PrivateKey))
			if err != nil {
				fmt.Println(err)
				return
			}

			key = jwKey
		}
		// if the user specified outputing an octek key binary file, derive a key from the RSA
		// private key. Output the salt and the label so that the key can be re-derived by
		// entities in possesion of the private key.
		//
		// note that using a derived octet key is safe as long as the RSA key is not used in
		// other means.
		if outputOctetKeyfile {
			// use sha256 as hashing function for HKDF
			hash := sha256.New

			// public salt and label
			salt := make([]byte, hash().Size())
			var err error
			if importKeyCfg.KeyDerivation.Salt != "" {
				salt, err = hex.DecodeString(importKeyCfg.KeyDerivation.Salt)
			} else {
				_, err = rand.Read(salt)
			}

			if err != nil {
				fmt.Println(err)
				return
			}

			var labelString string
			if importKeyCfg.KeyDerivation.Label != "" {
				labelString = importKeyCfg.KeyDerivation.Label
			} else {
				labelString = "Symmetric Encryption Key"
			}

			hkdf := hkdf.New(hash, jwKey.D(), salt, []byte(labelString))

			// derive key
			octKey = make([]byte, 32)
			if _, err := io.ReadFull(hkdf, octKey); err != nil {
				fmt.Println(err)
				return
			}

			fmt.Printf("Symmetric key %s (salt: %s label: %s)\n", hex.EncodeToString(octKey), hex.EncodeToString(salt), labelString)
		}
	} else if importKeyCfg.Key.KTY == "oct-HSM" || importKeyCfg.Key.KTY == "" {
		// if not specified, default is to generate an OCT key

		var err error

		if keyHexString == "" {
			octKey = make([]byte, 32)
			rand.Read(octKey)
		} else {
			octKey, err = hex.DecodeString(keyHexString)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

		fmt.Printf("Symmetric key %s\n", hex.EncodeToString(octKey))

		// note that if KeyOps is nil, the HSM will whitelist all operations
		key = OctKey{
			KTY:     "oct-HSM",
			KeyOps:  importKeyCfg.Key.KeyOps,
			K:       base64.RawURLEncoding.EncodeToString(octKey),
			KeySize: len(octKey) * 8,
		}
	} else {
		fmt.Println("Key not supported")
		return
	}

	if outputOctetKeyfile {
		keyfile, err := os.Create("keyfile.bin")
		if err != nil {
			fmt.Println(err)
			return
		}

		err = binary.Write(keyfile, binary.LittleEndian, octKey)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if AKVResponse, err := importKeyCfg.Key.AKV.ImportPlaintextKey(key, releasePolicy, importKeyCfg.Key.KID); err == nil {
		fmt.Println(AKVResponse.Key.KID)
		releasePolicyJSON, err := json.Marshal(releasePolicy)
		if err != nil {
			fmt.Println("marshalling release policy failed")
		} else {
			fmt.Println(string(releasePolicyJSON))
		}
	} else {
		fmt.Println(err)
	}
}
