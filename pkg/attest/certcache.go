// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
)

const (
	AzureCertCacheRequestURITemplate = "https://%s/%s/certificates/%s/%s?%s"
	AmdVCEKRequestURITemplate        = "https://%s/%s/%s?ucodeSPL=%d&snpSPL=%d&teeSPL=%d&blSPL=%d"
	AmdCertChainRequestURITemplate   = "https://%s/%s/cert_chain"
)

// CertCache contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertCache struct {
	AMD        bool   `json:"amd,omitempty"`
	Endpoint   string `json:"endpoint"`
	TEEType    string `json:"tee_type,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
}

// retrieveCertChain interacts with the cert cache service to fetch the cert chain of the
// chip identified by chipId running firmware identified by reportedTCB. These attributes
// are retrived from the attestation report.
func (certCache CertCache) retrieveCertChain(chipID string, reportedTCB uint64) ([]byte, error) {
	// HTTP GET request to cert cache service
	var uri string

	reportedTCBBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(reportedTCBBytes, reportedTCB)

	if certCache.AMD {
		// AMD cert cache endpoint returns the VCEK certificate in DER format
		uri = fmt.Sprintf(AmdVCEKRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, reportedTCBBytes[7], reportedTCBBytes[6], reportedTCBBytes[1], reportedTCBBytes[0])
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, errors.Wrapf(err, "certcache http get request failed")
		}
		derBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, err
		}
		// encode the VCEK cert in PEM format
		vcekPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

		// now retrieve the cert chain
		uri = fmt.Sprintf(AmdCertChainRequestURITemplate, certCache.Endpoint, certCache.TEEType)
		httpResponse, err = common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, errors.Wrapf(err, "certcache http get request failed")
		}
		certChainPEMBytes, err := common.HTTPResponseBody(httpResponse)
		if err != nil {
			return nil, errors.Wrapf(err, "pulling certchain response from get request failed")
		}

		// constuct full chain by appending the VCEK cert to the cert chain
		var fullCertChain []byte
		fullCertChain = append(fullCertChain, vcekPEMBytes[:]...)
		fullCertChain = append(fullCertChain, certChainPEMBytes[:]...)

		return fullCertChain, nil
	} else {
		uri = fmt.Sprintf(AzureCertCacheRequestURITemplate, certCache.Endpoint, certCache.TEEType, chipID, strconv.FormatUint(reportedTCB, 16), certCache.APIVersion)
		httpResponse, err := common.HTTPGetRequest(uri, false)
		if err != nil {
			return nil, errors.Wrapf(err, "certcache http get request failed")
		}
		return common.HTTPResponseBody(httpResponse)
	}
}

func (certCache CertCache) GetCertChain(chipID string, reportedTCB uint64) ([]byte, error) {
	return certCache.retrieveCertChain(chipID, reportedTCB)
}
