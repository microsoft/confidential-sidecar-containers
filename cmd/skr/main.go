// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	Identity              common.Identity
	EncodedUvmInformation common.UvmInformation
	ready                 bool
)

type AzureInformation struct {
	// Identifier of the managed identity to be used
	// for authenticating with AKV MHSM. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

type MAAAttestData struct {
	// MAA endpoint which authors the MAA token
	MAAEndpoint string `json:"maa_endpoint" binding:"required"`
	// Base64 encoded representation of runtime data to be encoded
	// as runtime claim in the MAA token
	RuntimeData string `json:"runtime_data" binding:"required"`
}

type RawAttestData struct {
	// Base64 encoded representation of runtime data whose hash digest
	// will be encoded as ReportData in the hardware attestation repport
	RuntimeData string `json:"runtime_data" binding:"required"`
}

type KeyReleaseData struct {
	// MAA endpoint which acts as authority to the key that needs to be released
	MAAEndpoint string `json:"maa_endpoint" binding:"required"`
	// MHSM endpoint from which the key is released
	MHSMEndpoint string `json:"mhsm_endpoint" binding:"required"`
	// key identifier for key to be released
	KID string `json:"kid" binding:"required"`
	// In the absence of managed identity assignment to the container group
	// an AAD token issued for authentication with MHSM resource may be included
	// in the request to release the key.
	AccessToken string `json:"access_token"`
}

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func getStatus(c *gin.Context) {
	if ready {
		c.JSON(http.StatusOK, gin.H{"message": "Status OK"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Status NOT OK"})
}

// postRawAttest retrieves a hardware attestation report signed by the
// Platform Security Processor and which encodes the hash digest of
// the request's RuntimeData in the attestation's ReportData
//
// - RuntimeData is expected to be a base64-standard-encoded string
func postRawAttest(c *gin.Context) {
	var attestData RawAttestData

	// Call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format").Error()})
		return
	}

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(EncodedUvmInformation.EncodedSecurityPolicy)

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrap(err, "decoding policy from Base64 format failed").Error()})
		return
	}

	// standard base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed").Error()})
		return
	}

	rawReport, err := attest.RawAttest(inittimeDataBytes, runtimeDataBytes)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"report": rawReport})
}

// postMAAAttest retrieves an attestation token issued by Microsoft Azure Attestation
// service which encodes the request's RuntimeData as a runtime claim
//
//   - RuntimeData is expected to be a base64-standard-encoded string
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation token
func postMAAAttest(c *gin.Context) {
	var attestData MAAAttestData

	// call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format").Error()})
		return
	}

	// base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed").Error()})
		return
	}

	maa := attest.MAA{
		Endpoint:   attestData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	maaToken, err := attest.Attest(maa, runtimeDataBytes, EncodedUvmInformation)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"token": maaToken})
}

// postKeyRelease retrieves a secret previously imported to Azure Key Vault MHSM
//
//   - MHSMEndpoint is the uri to the MHSM from which the secret will be retrieved
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation claims presented to the MSHM during secure
//     key release operation. It needs to be the same as the authority defined in the
//     SKR policy when the secret was imported to the MHSM.
//   - KID is the key identifier of the secret to be retrieved.
func postKeyRelease(c *gin.Context) {
	var newKeyReleaseData KeyReleaseData

	// Call BindJSON to bind the received JSON to KeyReleaseData
	if err := c.ShouldBindJSON(&newKeyReleaseData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format")})
		return
	}

	mhsm := skr.MHSM{
		Endpoint:    newKeyReleaseData.MHSMEndpoint,
		APIVersion:  "api-version=7.3-preview",
		BearerToken: newKeyReleaseData.AccessToken,
	}

	maa := attest.MAA{
		Endpoint:   newKeyReleaseData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       newKeyReleaseData.KID,
		Authority: maa,
		MHSM:      mhsm,
	}

	keyBytes, err := skr.SecureKeyRelease(Identity, skrKeyBlob, EncodedUvmInformation)

	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": hex.EncodeToString(keyBytes)})
}

func setupServer(identity common.Identity) *gin.Engine {

	Identity = identity

	logrus.Debugf("Setting security policy to %s", EncodedUvmInformation.EncodedSecurityPolicy)
	logrus.Debugf("Setting platform certs to %s", EncodedUvmInformation.CertChain)
	logrus.Debugf("Setting uvm reference to %s", EncodedUvmInformation.EncodedUvmReferenceInfo)

	r := gin.Default()

	r.GET("/status", getStatus)
	r.POST("/attest/raw", postRawAttest)

	// the implementation of attest/maa and key/release APIs call MAA service
	// to retrieve a MAA token. The MAA API requires that the request carries
	// the certificate chain endording the signing key of the hardware attestation.
	// Hence, these APIs are exposed only if the platform certificate information
	// has been provided at startup time.
	if EncodedUvmInformation.CertChain != "" {
		r.POST("/attest/maa", postMAAAttest)
		r.POST("/key/release", postKeyRelease)
	}

	ready = true

	return r
}

func main() {

	azureInfoBase64string := flag.String("base64", "", "optional base64-encoded json string with azure information")
	logLevel := flag.String("loglevel", "debug", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")
	port := flag.String("port", "8080", "Port on which to listen")

	// WARNING!!!
	// If the security policy does not control the arguments to this process then
	// this hostname could be set to 0.0.0.0 (an external interface) rather than 127.0.0.1 (visible only
	// witin the container group/pod)and so expose the attestation and key release outside of the secure uvm

	// Leaving this line here, as a comment, to aid debugging.
	// hostname := flag.String("hostname", "localhost", "address on which to listen (dangerous)")
	localhost := "localhost"
	hostname := &localhost

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Infof("Args:")
	logrus.Debugf("   Log Level:     %s", *logLevel)
	logrus.Debugf("   Log File:      %s", *logFile)
	logrus.Debugf("   Port:          %s", *port)
	logrus.Debugf("   Hostname:      %s", *hostname)
	logrus.Debugf("   azure info:    %s", *azureInfoBase64string)

	EncodedUvmInformation, err = common.GetUvmInfomation() // from the env.
	if err != nil {
		logrus.Fatalf("Failed to extract UVM_* environment variables: %s", err.Error())
	}

	info := AzureInformation{}

	// Decode base64 attestation information only if it s not empty
	if *azureInfoBase64string != "" {
		bytes, err := base64.StdEncoding.DecodeString(*azureInfoBase64string)
		if err != nil {
			logrus.Fatalf("Failed to decode base64: %s", err.Error())
		}

		err = json.Unmarshal(bytes, &info)
		if err != nil {
			logrus.Fatalf("Failed to unmarshal: %s", err.Error())
		}
	}

	// See above comment about hostname and risk of breaking confidentiality
	url := *hostname + ":" + *port

	setupServer(info.Identity).Run(url)
}
