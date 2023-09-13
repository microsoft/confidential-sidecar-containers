// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

/*
	This is not currently strictly required as these platform certificates from AMD are
	now provided by GCS to containers as an environment variable UVM_HOST_AMD_CERTIFICATE

	It is required for the tests and when running outside of Azure.
*/

import (
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"crypto/x509"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
)

const (
	AzureCertCacheRequestURITemplate = "https://%s/%s/certificates/%s/%s?%s"
	AmdVCEKRequestURITemplate        = "https://%s/%s/%s?ucodeSPL=%d&snpSPL=%d&teeSPL=%d&blSPL=%d"
	AmdCertChainRequestURITemplate   = "https://%s/%s/cert_chain"
	LocalTHIMUriTemplate             = "http://%s" // To-Do update once we know what this looks like
)

const (
	BlSplTcbmByteIndex    = 0
	TeeSplTcbmByteIndex   = 1
	TcbSpl_4TcbmByteIndex = 2
	TcbSpl_5TcbmByteIndex = 3
	TcbSpl_6TcbmByteIndex = 4
	TcbSpl_7TcbmByteIndex = 5
	SnpSplTcbmByteIndex   = 6
	UcodeSplTcbmByteIndex = 7
)

// can't find any documentation on why the 3rd byte of the Certificate.Extensions byte array is the one that matters
// all the byte arrays for the tcb values are of length 3 and fit the format [2 1 IMPORTANT_VALUE]
const x509CertExtensionsValuePos = 2

// parses the cached CertChain and returns the VCEK leaf certificate
// Subject of the (x509) VCEK certificate (CN=SEV-VCEK)
func GetVCEKFromCertChain(certChain []byte) (*x509.Certificate, error) {
	currChain := certChain
	// iterate through the certificates in the chain
	for len(currChain) > 0 {
		var block *pem.Block
		block, currChain = pem.Decode(currChain)
		if block.Type == "CERTIFICATE" {
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			// check if this is the correct certificate
			if certificate.Subject.CommonName == "SEV-VCEK" {
				return certificate, nil
			}
		}
	}
	return nil, errors.New("No certificate chain found")
}

// parses the VCEK certificate to return the TCB version
// fields reprocessed back into a uint64 to compare against the `ReportedTCB` in the fetched attestation report
func ParseVCEK(certChain []byte) ( /*tcbVersion*/ uint64, error) {
	vcekCert, err := GetVCEKFromCertChain(certChain)
	if err != nil {
		return 0, err
	}

	tcbValues := make([]byte, 8) // TCB version is 8 bytes
	// parse extensions to update the THIM URL and get TCB Version
	for _, ext := range vcekCert.Extensions {
		switch ext.Id.String() {
		// Based on Table 9 of SEV-SNP Firmware ABI Specification
		// https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification

		// blSPL
		case "1.3.6.1.4.1.3704.1.3.1":
			tcbValues[BlSplTcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// teeSPL
		case "1.3.6.1.4.1.3704.1.3.2":
			tcbValues[TeeSplTcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// spl_4
		case "1.3.6.1.4.1.3704.1.3.4":
			tcbValues[TcbSpl_4TcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// spl_5
		case "1.3.6.1.4.1.3704.1.3.5":
			tcbValues[TcbSpl_5TcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// spl_6
		case "1.3.6.1.4.1.3704.1.3.6":
			tcbValues[TcbSpl_6TcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// spl_7
		case "1.3.6.1.4.1.3704.1.3.7":
			tcbValues[TcbSpl_7TcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// snpSPL
		case "1.3.6.1.4.1.3704.1.3.3":
			tcbValues[SnpSplTcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		// ucodeSPL
		case "1.3.6.1.4.1.3704.1.3.8":
			tcbValues[UcodeSplTcbmByteIndex] = ext.Value[x509CertExtensionsValuePos]
		}
	}

	return binary.LittleEndian.Uint64(tcbValues), nil
}

// CertFetcher contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertFetcher struct {
	EndpointType string `json:"endpoint_type"` // AMD, AzCache, LocalTHIM
	Endpoint     string `json:"endpoint"`
	TEEType      string `json:"tee_type,omitempty"`
	APIVersion   string `json:"api_version,omitempty"`
}

// Creates default AMD CertFetcher instance for Milan
func DefaultAMDMilanCertFetcherNew() CertFetcher {
	return CertFetcher{
		EndpointType: "AMD",
		Endpoint:     "kdsintf.amd.com/vcek/v1",
		TEEType:      "Milan",
		APIVersion:   "",
	}
}

// Creates default Azure CertFetcher instance for SEV-SNP
func DefaultAzureCertFetcherNew() CertFetcher {
	return CertFetcher{
		EndpointType: "AzCache",
		Endpoint:     "global.acccache.azure.net",
		TEEType:      "SevSnpVM",
		APIVersion:   "api-version=2020-10-15-preview",
	}
}

const (
	defaultRetryBaseSec    = 10
	defaultRetryMaxRetries = 2
)

func fetchWithRetry(requestURL string, baseSec int, maxRetries int, httpRequestFunc func(string) (*http.Response, error)) ([]byte, error) {
	if maxRetries < 0 {
		return nil, fmt.Errorf("invalid `maxRetries` value")
	}
	var err error
	var res *http.Response
	retryCount := 0
	for retryCount <= maxRetries {
		if retryCount > 0 {
			// Exponential backoff
			maxDelay := math.Pow(float64(baseSec), float64(retryCount))
			delaySec := rand.Float64() * maxDelay
			delaySecInt := math.Min(math.MaxInt64, delaySec)
			time.Sleep(time.Duration(delaySecInt) * time.Second)
		}
		if httpRequestFunc != nil {
			res, err = httpRequestFunc(requestURL)
		} else {
			res, err = http.Get(requestURL)
		}
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

// retrieveCertChain interacts with the cert cache service to fetch the cert chain of the
// chip identified by chipId running firmware identified by reportedTCB. These attributes
// are retrieved from the attestation report.
// Returns the cert chain as a bytes array, the TCBM from the local THIM cert cache is as a string
// (only in the case of a local THIM endpoint), and any errors encountered
func (certFetcher CertFetcher) retrieveCertChain(chipID string, reportedTCB uint64) ([]byte, uint64, error) {
	// HTTP GET request to cert cache service
	var uri string
	var thimTcbm uint64
	var thimCerts common.THIMCerts

	reportedTCBBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(reportedTCBBytes, reportedTCB)

	if certFetcher.Endpoint != "" {
		switch certFetcher.EndpointType {
		case "AMD":
			// Fetch platform certificate from AMD endpoint
			// https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification
			// AMD cert cache endpoint returns the VCEK certificate in DER format
			uri = fmt.Sprintf(AmdVCEKRequestURITemplate, certFetcher.Endpoint, certFetcher.TEEType, chipID, reportedTCBBytes[UcodeSplTcbmByteIndex], reportedTCBBytes[SnpSplTcbmByteIndex], reportedTCBBytes[TeeSplTcbmByteIndex], reportedTCBBytes[BlSplTcbmByteIndex])
			derBytes, err := fetchWithRetry(uri, defaultRetryBaseSec, defaultRetryMaxRetries, nil)
			if err != nil {
				return nil, reportedTCB, err
			}
			// encode the VCEK cert in PEM format
			vcekPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

			// now retrieve the cert chain
			uri = fmt.Sprintf(AmdCertChainRequestURITemplate, certFetcher.Endpoint, certFetcher.TEEType)
			certChainPEMBytes, err := fetchWithRetry(uri, defaultRetryBaseSec, defaultRetryMaxRetries, nil)
			if err != nil {
				return nil, reportedTCB, errors.Wrapf(err, "pulling AMD certchain response from get request failed")
			}

			// constuct full chain by appending the VCEK cert to the cert chain
			fullCertChain := append(vcekPEMBytes, certChainPEMBytes[:]...)

			return fullCertChain, reportedTCB, nil
		case "LocalTHIM":
			uri = fmt.Sprintf(LocalTHIMUriTemplate, certFetcher.Endpoint)
			THIMCertsBytes, err := fetchWithRetry(uri, defaultRetryBaseSec, defaultRetryMaxRetries, getThimCertsHttp)
			if err != nil {
				return nil, thimTcbm, errors.Wrapf(err, "pulling certchain response from get request failed")
			}

			thimCerts, err = common.ParseTHIMCertsFromByte(THIMCertsBytes)
			if err != nil {
				return nil, thimTcbm, errors.Wrapf(err, "certcache failed to get local certs")
			}

			thimTcbm, err = common.ParseTHIMTCBM(thimCerts)
			if err != nil {
				return nil, thimTcbm, errors.Wrapf(err, "failed to parse THIM TCBM")
			}

			return common.ConcatenateCerts(thimCerts), thimTcbm, nil
		case "AzCache":
			uri = fmt.Sprintf(AzureCertCacheRequestURITemplate, certFetcher.Endpoint, certFetcher.TEEType, chipID, strconv.FormatUint(reportedTCB, 16), certFetcher.APIVersion)
			certChain, err := fetchWithRetry(uri, defaultRetryBaseSec, defaultRetryMaxRetries, nil)
			if err != nil {
				return nil, thimTcbm, errors.Wrapf(err, "pulling certchain response from AzCache get request failed")
			}
			thimTcbm, err = ParseVCEK(certChain)
			if err != nil {
				return nil, thimTcbm, errors.Wrapf(err, "AzCache failed to parse VCEK from cert chain")
			}
			return certChain, thimTcbm, nil
		default:
			return nil, thimTcbm, errors.Errorf("invalid endpoint type: %s", certFetcher.EndpointType)
		}
	} else {
		return nil, thimTcbm, errors.Errorf("failed to retrieve cert chain: certificate endpoint not set")
	}
}

/*
Fetches platform certificates of SEV-SNP VM.

The certificates are concatenation of VCEK, ASK, and ARK certificates (PEM format, in that order).
https://www.amd.com/en/support/tech-docs/versioned-chip-endorsement-key-vcek-certificate-and-kds-interface-specification

It also returns TCB as uint64 (useful only when "LocalTHIM" is used for EndpointType).
*/
func (certFetcher CertFetcher) GetCertChain(chipID string, reportedTCB uint64) ([]byte, uint64, error) {
	return certFetcher.retrieveCertChain(chipID, reportedTCB)
}

func getThimCertsHttp(uri string) (*http.Response, error) {
	httpResponse, err := common.HTTPGetRequest(uri, true)
	if err != nil {
		return nil, errors.Wrapf(err, "pulling thim certs request failed")
	}

	return httpResponse, nil
}

func (certFetcher CertFetcher) GetThimCerts(uri string) (*common.THIMCerts, error) {
	uri = fmt.Sprintf(LocalTHIMUriTemplate, uri)
	THIMCertsBytes, err := fetchWithRetry(uri, defaultRetryBaseSec, defaultRetryMaxRetries, getThimCertsHttp)
	if err != nil {
		return nil, errors.Wrapf(err, "Fetching THIM Certs with retries failed.")
	}
	fmt.Println("length of thim certbytes is", len(THIMCertsBytes))
	fmt.Println("actually print out the bytes\n", THIMCertsBytes)
	thimCerts, err := common.ParseTHIMCertsFromByte(THIMCertsBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Parse THIM Certs from bytes failed.")
	}

	return &thimCerts, nil
}
