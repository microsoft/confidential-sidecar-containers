package httpginendpoints

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var ready bool

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
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format").Error()})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set")})
		return
	}

	// base64 decode the incoming encoded security policy
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInfo.EncodedSecurityPolicy)

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

	var attestationReportFetcher attest.AttestationReportFetcher
	if _, err := os.Stat("/dev/sev"); errors.Is(err, os.ErrNotExist) {
		hostData := attest.GenerateMAAHostData(inittimeDataBytes)
		attestationReportFetcher = attest.UnsafeNewFakeAttestationReportFetcher(hostData)
	} else {
		attestationReportFetcher = attest.NewAttestationReportFetcher()
	}
	reportData := attest.GenerateMAAReportData(runtimeDataBytes)
	rawReport, err := attestationReportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"report": rawReport})
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

	certState, ok := c.MustGet("certState").(*attest.CertState)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("serverCertState is not set")})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set")})
		return
	}

	maaToken, err := certState.Attest(maa, runtimeDataBytes, *uvmInfo)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": errors.Wrapf(err, "invalid request format")})
		return
	}

	akv := skr.AKV{
		Endpoint:    newKeyReleaseData.AKVEndpoint,
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
		AKV:       akv,
	}

	certState, ok := c.MustGet("certState").(*attest.CertState)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("serverCertState is not set")})
		return
	}

	identity, ok := c.MustGet("identity").(*common.Identity)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("workload identity is not set")})
		return
	}

	uvmInfo, ok := c.MustGet("uvmInfo").(*common.UvmInformation)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("uvmInfo is not set")})
		return
	}

	jwKey, err := skr.SecureKeyRelease(*identity, *certState, skrKeyBlob, *uvmInfo)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	logrus.Debugf("Key released of type %s", jwKey.KeyType())

	jwkJSONBytes, err := json.Marshal(jwKey)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
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
