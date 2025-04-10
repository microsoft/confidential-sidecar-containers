package httpginendpoints

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var ready bool

const (
	AZURE_CLIENT_ID            = "AZURE_CLIENT_ID"
	AZURE_TENANT_ID            = "AZURE_TENANT_ID"
	AZURE_FEDERATED_TOKEN_FILE = "AZURE_FEDERATED_TOKEN_FILE"
)

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
	// AKV endpoint from which the key is released
	AKVEndpoint string `json:"akv_endpoint" binding:"required"`
	// key identifier for key to be released
	KID string `json:"kid" binding:"required"`
	// In the absence of managed identity assignment to the container group
	// an AAD token issued for authentication with AKV resource may be included
	// in the request to release the key.
	AccessToken string `json:"access_token"`
}

func SetServerReady() {
	ready = true
}

func GetStatus(c *gin.Context) {
	if ready {
		c.JSON(http.StatusOK, gin.H{"message": "Status OK"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Status NOT OK"})
}

// PostRawAttest retrieves a hardware attestation report signed by the
// Platform Security Processor and which encodes the hash digest of
// the request's RuntimeData in the attestation's ReportData
//
// - RuntimeData is expected to be a base64-standard-encoded string
func PostRawAttest(c *gin.Context) {
	var attestData RawAttestData

	// Call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format\n%s", skr.ERROR_STRING).Error()})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set\n" + skr.ERROR_STRING)})
		return
	}

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInfo.EncodedSecurityPolicy)

	if err != nil {
		// TODO: review this StatusForbidden - surely should be StatusInternalServerError
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrapf(err, "decoding policy from Base64 format failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	// standard base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	var attestationReportFetcher attest.AttestationReportFetcher
	if attest.IsSNPVM() {
		attestationReportFetcher, err = attest.NewAttestationReportFetcher()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "failure to create attestationReportFetcher\n%s", skr.ERROR_STRING).Error()})
		}
	} else {
		// Use dummy report if SEV device is not available
		logrus.Debug("UnsafeNewFakeAttestationReportFetcher...")
		hostData := attest.GenerateMAAHostData(inittimeDataBytes)
		attestationReportFetcher = attest.UnsafeNewFakeAttestationReportFetcher(hostData)
	}

	reportData := attest.GenerateMAAReportData(runtimeDataBytes)
	rawReport, err := attestationReportFetcher.FetchAttestationReportHex(reportData)
	// TODO: review this StatusForbidden - surely should be StatusInternalServerError
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrapf(err, "failure to fetch attestation report hex\n%s", skr.ERROR_STRING).Error()})
	}

	c.JSON(http.StatusOK, gin.H{"report": rawReport})
}

/*
	As PostRawAttest but also the various certificates and the UVM reference info so as to suit the Privacy Sandbox.

	see https://github.com/microsoft/azure-privacy-sandbox-kms/blob/main/test/attestation-samples/snp.json
	{
	    "endorsed_tcb": "0300000000000873",
	    "endorsements": "base64 encoded certificate chain",
	    "evidence": "base64 encoded attestation report",
	    "uvm_endorsements": "base64 encoded uvm reference info COSESign1 document",
	}

	This is mostly easily obtainable from /security-context-* but this endpoint is provided for convenience.
	It may also choose to do a better job of fetching the AMD certs, e.g. other sources than the local THIM and
	with better retries.
*/

/*
	Notice that the serialised names in CombinedAttestationData must follow the c++ code in the Privacy Sandbox dataplane shared
	library. The member names must start with a capital due to the public/private convention in golang or the
	value will not be emitted in the JSON.
*/

type CombinedAttestationData struct {
	// PSP TCB version
	EndorsedTcb string `json:"endorsed_tcb"`
	// AMD certificate chain matching the attestation report
	Endorsements string `json:"endorsements"`
	// attestation report base64 encoded (note that this is different to the raw endpoint which returns it hex encoded)
	Evidence string `json:"evidence"`
	// In the absence of managed identity assignment to the container group
	// an AAD token issued for authentication with AKV resource may be included
	// in the request to release the key.
	UvmEndorsements string `json:"uvm_endorsements"`
}

func PostCombinedAttest(c *gin.Context) {
	var attestData RawAttestData

	logrus.Debug("PostCombinedAttest...")
	// Call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format\n%s", skr.ERROR_STRING).Error()})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set\n" + skr.ERROR_STRING)})
		return
	}

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInfo.EncodedSecurityPolicy)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "decoding policy from Base64 format failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	// standard base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	var attestationReportFetcher attest.AttestationReportFetcher
	if attest.IsSNPVM() {
		attestationReportFetcher, err = attest.NewAttestationReportFetcher()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "failure to create attestationReportFetcher\n%s", skr.ERROR_STRING).Error()})
			return
		}
	} else {
		// Use dummy report if SEV device is not available
		logrus.Debug("UnsafeNewFakeAttestationReportFetcher...")
		hostData := attest.GenerateMAAHostData(inittimeDataBytes)
		attestationReportFetcher = attest.UnsafeNewFakeAttestationReportFetcher(hostData)
	}

	reportData := attest.GenerateMAAReportData(runtimeDataBytes)
	rawReport, err := attestationReportFetcher.FetchAttestationReportByte(reportData)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.Wrapf(err, "failure to fetch attestation report bytes\n%s", skr.ERROR_STRING).Error()})
		return
	}

	certs := uvmInfo.InitialCerts
	certsB64 := base64.StdEncoding.EncodeToString([]byte(certs.VcekCert + certs.CertificateChain))

	combinedAttestationData := CombinedAttestationData{
		EndorsedTcb:     certs.Tcbm,
		Endorsements:    certsB64,
		Evidence:        base64.StdEncoding.EncodeToString(rawReport),
		UvmEndorsements: uvmInfo.EncodedUvmReferenceInfo,
	}

	// c.JSON will encode the CombinedAttestationData struct to JSON
	c.JSON(http.StatusOK, combinedAttestationData)
}

// PostMAAAttest retrieves an attestation token issued by Microsoft Azure Attestation
// service which encodes the request's RuntimeData as a runtime claim
//
//   - RuntimeData is expected to be a base64-standard-encoded string
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation token
func PostMAAAttest(c *gin.Context) {
	var attestData MAAAttestData

	// call BindJSON to bind the received JSON to AttestData
	if err := c.ShouldBindJSON(&attestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format\n%s", skr.ERROR_STRING).Error()})
		return
	}

	// base64 decode the incoming runtime data
	runtimeDataBytes, err := base64.StdEncoding.DecodeString(attestData.RuntimeData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "decoding base64-encoded runtime data of request failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	maa := common.MAA{
		Endpoint:   attestData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	certState, ok := c.MustGet("certState").(*attest.CertState)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("serverCertState is not set\n" + skr.ERROR_STRING)})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set\n" + skr.ERROR_STRING)})
		return
	}

	maaToken, err := certState.Attest(maa, runtimeDataBytes, *uvmInfo)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrapf(err, "attestation failed\n%s", skr.ERROR_STRING).Error()})
	}

	c.JSON(http.StatusOK, gin.H{"token": maaToken})
}

// PostKeyRelease retrieves a secret previously imported to Azure Key Vault
//
//   - AKVEndpoint is the uri to the key vault from which the secret will be retrieved
//   - MAAEndpoint is the uri to the Microsoft Azure Attestation service endpoint which
//     will author and sign the attestation claims presented to the MSHM during secure
//     key release operation. It needs to be the same as the authority defined in the
//     SKR policy when the secret was imported to the AKV.
//   - KID is the key identifier of the secret to be retrieved.
func PostKeyRelease(c *gin.Context) {
	var newKeyReleaseData KeyReleaseData

	// Call BindJSON to bind the received JSON to KeyReleaseData
	if err := c.ShouldBindJSON(&newKeyReleaseData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format\n%s", skr.ERROR_STRING)})
		return
	}

	akv := common.AKV{
		Endpoint:    newKeyReleaseData.AKVEndpoint,
		APIVersion:  "api-version=7.4",
		BearerToken: newKeyReleaseData.AccessToken,
	}

	maa := common.MAA{
		Endpoint:   newKeyReleaseData.MAAEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := common.KeyBlob{
		KID:       newKeyReleaseData.KID,
		Authority: maa,
		AKV:       akv,
	}

	certState, ok := c.MustGet("certState").(*attest.CertState)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("serverCertState is not set\n" + skr.ERROR_STRING)})
		return
	}

	identity, ok := c.MustGet("identity").(*common.Identity)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("workload identity is not set\n" + skr.ERROR_STRING)})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set\n" + skr.ERROR_STRING)})
		return
	}

	jwKey, err := skr.SecureKeyRelease(*identity, *certState, skrKeyBlob, *uvmInfo)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrapf(err, "secure key release failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	logrus.Debugf("Key released of type %s", jwKey.KeyType())

	jwkJSONBytes, err := json.Marshal(jwKey)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errors.Wrapf(err, "json marshalling of JWK failed\n%s", skr.ERROR_STRING).Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": string(jwkJSONBytes)})
}

func RegisterGlobalStates(certState *attest.CertState, identity *common.Identity, uvmInfo *common.UvmInformation) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("certState", certState)
		c.Set("identity", identity)
		c.Set("uvmInfo", uvmInfo)
		c.Next()
	}
}
