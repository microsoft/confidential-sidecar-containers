// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"math/rand"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	AttestRequestURITemplate = "https://%s/attest/%s?%s"
)

// MAA contains information about the MAA service that acts as the
// author of the claims
type MAA struct {
	Endpoint   string `json:"endpoint"`
	TEEType    string `json:"tee_type,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
}

// MAA SNP Request Body class
type maaReport struct {
	SNPReport    string `json:"SnpReport"`
	CertChain    string `json:"VcekCertChain"`
	Endorsements string `json:"Endorsements,omitempty"`
}

// MAA expects Endorsements to contain a json array (named "Uvm") of base64url encoded
// cosesign1 blobs (signed by PRSS on behalf of ContainerPlat)

type maaEndorsements struct {
	Uvm []string `json:"Uvm"`
}

type attestedData struct {
	Data     string `json:"data"`
	DataType string `json:"dataType"`
}

type attestSNPRequestBody struct {
	Report       string       `json:"report"`
	RuntimeData  attestedData `json:"runtimeData"`  // lowecase t
	InittimeData attestedData `json:"initTimeData"` // upercase T
	Nonce        uint64       `json:"nonce"`
}

// newAttestSNPRequestBody constructs a MAA attest request. It contains (i) the base64
// URL encoding of a bundle containing the hardware attestation report (SNPReport)
// and the certificate chain, (ii) the  runtime data (base64 URL encoding of the public
// wrapping key), (iii) the inittime data (base64 URL encoding of the security policy),
// and (iv) a nonce
func newAttestSNPRequestBody(snpAttestationReport []byte, vcekCertChain []byte, policyBlob []byte, keyBlob []byte, uvmReferenceInfo []byte) (*attestSNPRequestBody, error) {
	var request attestSNPRequestBody

	var base64urlEncodedUvmReferenceInfo string
	if len(uvmReferenceInfo) > 0 {
		base64urlEncodedUvmReferenceInfo = base64.URLEncoding.EncodeToString(uvmReferenceInfo)
	}
	logrus.Debugf("base64urlEncodedUvmReferenceInfo: %s", base64urlEncodedUvmReferenceInfo)

	if GenerateTestData {
		os.WriteFile("body.uvm_reference_info.bin", uvmReferenceInfo, 0644)
		os.WriteFile("body.uvm_reference_info.base64url", []byte(base64urlEncodedUvmReferenceInfo), 0644)
	}

	var base64urlEncodedmaaEndorsement string
	if len(base64urlEncodedUvmReferenceInfo) > 0 {
		maaEndorsement := maaEndorsements{
			Uvm: []string{base64urlEncodedUvmReferenceInfo},
		}

		logrus.Info("Marshalling MAA Endorsement...")
		var err error
		maaEndorsementJSONBytes, err := json.Marshal(maaEndorsement)
		if err != nil {
			return nil, errors.Wrapf(err, "marhalling maa endorsement failed")
		}
		base64urlEncodedmaaEndorsement = base64.URLEncoding.EncodeToString(maaEndorsementJSONBytes)

		if GenerateTestData {
			os.WriteFile("body.endorsements.bin", maaEndorsementJSONBytes, 0644)
			os.WriteFile("body.endorsements.base64url", []byte(base64urlEncodedmaaEndorsement), 0644)
		}
	}

	// the maa report is a bundle of the signed attestation report and
	// the cert chain that endorses the signing key
	maaReport := maaReport{
		SNPReport:    base64.URLEncoding.EncodeToString(snpAttestationReport),
		CertChain:    base64.URLEncoding.EncodeToString(vcekCertChain),
		Endorsements: base64urlEncodedmaaEndorsement,
	}

	logrus.Debugf("Marshalling maaReport: %+v", maaReport)
	maaReportJSONBytes, err := json.Marshal(maaReport)
	if err != nil {
		return nil, errors.Wrapf(err, "marhalling maa Report failed")
	}

	request.Report = base64.URLEncoding.EncodeToString(maaReportJSONBytes)

	if GenerateTestData {
		os.WriteFile("body.maa_report.json", maaReportJSONBytes, 0644)
		os.WriteFile("body.report.base64url", []byte(request.Report), 0644)
	}

	// the key blob is passed as runtime data
	request.RuntimeData = attestedData{
		Data:     base64.URLEncoding.EncodeToString(keyBlob),
		DataType: "JSON", // Binary not allowed, must be JSON? - see https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm?tabs=HTTP#datatype
	}

	// the policy blob is passed as inittime data
	// As of today we CANNOT pass the policy as it is rego, so not good json and only json
	// is currently supported by MAA, not binary.
	if false && policyBlob != nil {
		request.InittimeData = attestedData{
			Data:     base64.URLEncoding.EncodeToString(policyBlob),
			DataType: "binary", // rego really
		}
	}

	rand.New(rand.NewSource(time.Now().UnixNano()))
	request.Nonce = rand.Uint64()

	return &request, nil
}

// attest interracts with MAA to fetch an MAA token. A valid MAA attest request requires a
// cert chain that endorses the signing key of the attestation report, the hardware attestation
// report, and additional evidence, including the policy blob and the key blob, whose hash have
// been included in the HOST_DATA and REPORT_DATA fields of the attestation report, respectively.
//
// MAA validates the signature of the attestation report using the public key of the leaf
// certificate of the cert chain, validates the cert chain, and finally validates the additional
// evidence against the HOST_DATA and REPORT_DATA fields of the validated attestation report.
// Upon successful attestation, MAA issues an MAA token which presents the policy blob as inittime
// claims and the key blob as runtime claims.
//
// Note, the using the leaf cert will be changed to a DID based scheme similar to fragments.
func (maa MAA) Attest(SNPReportHexBytes []byte, vcekCertChain []byte, policyBlobBytes []byte, keyBlobBytes []byte, encodedUvmReferenceInfo []byte) (MAAToken string, err error) {
	// Construct attestation request that contain the four attributes
	logrus.Info("Constructing MAA Attestation Request...")
	request, err := newAttestSNPRequestBody(SNPReportHexBytes, vcekCertChain, policyBlobBytes, keyBlobBytes, encodedUvmReferenceInfo)
	if err != nil {
		return "", errors.Wrapf(err, "creating new AttestSNPRequestBody failed")
	}

	logrus.Debugf("Marshalling MAA Attestation Request: %+v", request)
	maaRequestJSONData, err := json.Marshal(request)
	if err != nil {
		return "", errors.Wrapf(err, "marshalling maa request failed")
	}
	logrus.Debugf("MAA Request: %s\n", string(maaRequestJSONData))

	if GenerateTestData {
		os.WriteFile("request.json", maaRequestJSONData, 0644)
	}

	// HTTP POST request to MAA service
	uri := fmt.Sprintf(AttestRequestURITemplate, maa.Endpoint, maa.TEEType, maa.APIVersion)
	logrus.Debugf("Posting MAA Attestation Request to %s", uri)
	httpResponse, err := HTTPPRequest("POST", uri, maaRequestJSONData, "")
	if err != nil {
		return "", errors.Wrapf(err, "maa post request failed")
	}

	httpResponseBodyBytes, err := HTTPResponseBody(httpResponse)
	if err != nil {
		logrus.Debugf("MAA Response header: %v", httpResponse)
		logrus.Debugf("MAA Response body bytes: %s", string(httpResponseBodyBytes))
		return "", errors.Wrapf(err, "pulling maa post response failed")
	}

	// Retrieve MAA token from the JWT response returned by MAA
	var maaResponse struct {
		Token string
	}

	logrus.Info("Unmarshalling MAA Attestation Response...")
	if err = json.Unmarshal(httpResponseBodyBytes, &maaResponse); err != nil {
		return "", errors.Wrapf(err, "unmarshalling maa http response body failed")
	}

	if maaResponse.Token == "" {
		return "", errors.New("empty token string in maa response")
	}

	logrus.Debugf("MAA Token: %s", maaResponse.Token)
	return maaResponse.Token, nil
}
