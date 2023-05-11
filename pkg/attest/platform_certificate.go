package attest

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"time"
)

const (
	defaultBaseSec    = 2
	defaultMaxRetries = 5
)

const (
	AMD_CERTIFICATE_HOST   = "https://kdsintf.amd.com"
	AZURE_CERTIFICATE_HOST = "https://global.acccache.azure.net"

	DEFAULT_SECURITY_CONTEXT_ENVVAR = "UVM_SECURITY_CONTEXT_DIR" // SEV-SNP ACI deployments
	UVM_ENDORSEMENTS_FILE_NAME      = "reference-info-base64"
	PLATFORM_CERTIFICATES_FILE_NAME = "host-amd-cert-base64"
)

func fetchWithRetry(requestURL string, baseSec int, maxRetries int) ([]byte, error) {
	if maxRetries < 0 {
		return nil, fmt.Errorf("invalid `maxRetries` value")
	}
	var err error
	retryCount := 0
	for retryCount <= maxRetries {
		if retryCount > 0 {
			// Exponential backoff
			maxDelay := math.Pow(float64(baseSec), float64(retryCount))
			delaySec := rand.Float64() * maxDelay
			delaySecInt := math.Min(math.MaxInt64, delaySec)
			time.Sleep(time.Duration(delaySecInt) * time.Second)
		}
		res, err := http.Get(requestURL)
		if err != nil {
			retryCount++
			continue
		}
		if 200 <= res.StatusCode && res.StatusCode < 300 {
			// Got successful status code 2xx
			defer res.Body.Close()
			resBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				retryCount++
				continue
			}
			return resBody, nil
		} else if res.StatusCode == 408 || res.StatusCode == 429 || 500 <= res.StatusCode {
			// Got status code that is worth to retry
			retryCount++
			continue
		} else {
			// Got status code that is not worth to retry
			defer res.Body.Close()
			resBody, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return nil, fmt.Errorf("got error while handling non successful response with status code %d: %s", res.StatusCode, err)
			}
			return nil, fmt.Errorf("GET request failed with status code %d: %s", res.StatusCode, resBody)
		}
	}
	return nil, err
}

func fetchPlatformCertificateAzure(reportedTCBBytes [REPORTED_TCB_SIZE]byte, chipID string) ([]byte, error) {
	// Fetch platform certificate from Azure endpoint
	reportedTCB := binary.LittleEndian.Uint64(reportedTCBBytes[:])
	reportedTCBHex := fmt.Sprintf("%x", reportedTCB)
	requestURL := fmt.Sprintf("%s/SevSnpVM/certificates/%s/%s?api-version=2020-10-15-preview", AZURE_CERTIFICATE_HOST, chipID, reportedTCBHex)
	return fetchWithRetry(requestURL, defaultBaseSec, defaultMaxRetries)
}

func fetchPlatformCertificateAMD(reportedTCBBytes [REPORTED_TCB_SIZE]byte, chipID string) ([]byte, error) {
	// Fetch platform certificate from AMD endpoint
	// https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification

	boot_loader := reportedTCBBytes[0]
	tee := reportedTCBBytes[1]
	snp := reportedTCBBytes[6]
	microcode := reportedTCBBytes[7]
	const PRODUCT_NAME = "Milan"
	requestURL := fmt.Sprintf("%s/vcek/v1/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d", AMD_CERTIFICATE_HOST, PRODUCT_NAME, chipID, boot_loader, tee, snp, microcode)
	vcekCertDER, err := fetchWithRetry(requestURL, defaultBaseSec, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	vcek, err := x509.ParseCertificate(vcekCertDER)
	if err != nil {
		return nil, fmt.Errorf("Could not decode VCEK: %s", err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: vcek.Raw})

	requestURLChain := fmt.Sprintf("%s/vcek/v1/%s/cert_chain", AMD_CERTIFICATE_HOST, PRODUCT_NAME)
	certChain, err := fetchWithRetry(requestURLChain, defaultBaseSec, defaultMaxRetries)
	if err != nil {
		return nil, err
	}
	return append(cert, certChain...), nil
}

/*
TODO: Delete

Fetches platform certificates of SEV-SNP VM.

The endorsements are concatenation of VCEK, ASK, and ARK certificates (PEM format, in that order).
https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification
*/
func FetchPlatformCertificate(server string, reportedTCBBytes []byte, chipIDBytes []byte) ([]byte, error) {
	if server != "AMD" && server != "Azure" {
		return nil, fmt.Errorf("invalid platform certificate server: %s", server)
	}
	if len(reportedTCBBytes) != REPORTED_TCB_SIZE {
		return nil, fmt.Errorf("Length of reportedTCBBytes should be %d", REPORTED_TCB_SIZE)
	}
	if len(chipIDBytes) != CHIP_ID_SIZE {
		return nil, fmt.Errorf("Length of chipIDBytes should be %d", CHIP_ID_SIZE)
	}

	reportedTCB := [REPORTED_TCB_SIZE]byte{}
	copy(reportedTCB[:], reportedTCBBytes)
	chipID := hex.EncodeToString(chipIDBytes)
	if server == "Azure" {
		return fetchPlatformCertificateAzure(reportedTCB, chipID)
	} else {
		return fetchPlatformCertificateAMD(reportedTCB, chipID)
	}
}
