// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertState contains information about the certificate cache service
// that provides access to the certificate chain required upon attestation
type CertState struct {
	CertFetcher CertFetcher `json:"cert_cache"`
	Tcbm        uint64      `json:"tcbm"`
}

func (certState *CertState) RefreshCertChain(SNPReport SNPAttestationReport) ([]byte, error) {
	// TCB values not the same, try refreshing cert first
	vcekCertChain, thimTcbm, err := certState.CertFetcher.GetCertChain(SNPReport.ChipID, SNPReport.ReportedTCB)
	if err != nil {
		return nil, errors.Wrap(err, "refreshing CertChain failed")
	}
	certState.Tcbm = thimTcbm
	return vcekCertChain, nil
}

// Takes bytes and generate report data that MAA expects (SHA256 hash of arbitrary data).
func GenerateMAAReportData(inputBytes []byte) [REPORT_DATA_SIZE]byte {
	runtimeData := sha256.New()
	if inputBytes != nil {
		runtimeData.Write(inputBytes)
	}
	reportData := [REPORT_DATA_SIZE]byte{}
	runtimeDataBytes := runtimeData.Sum(nil)
	const sha256len = 32
	if len(runtimeDataBytes) != sha256len {
		panic(fmt.Errorf("length of sha256 hash should be %d bytes, but it is actually %d bytes", sha256len, len(runtimeDataBytes)))
	}
	if sha256len > REPORT_DATA_SIZE {
		panic(fmt.Errorf("generated hash is too large for report data. hash length: %d bytes, report data size: %d", sha256len, REPORT_DATA_SIZE))
	}
	copy(reportData[:sha256len], runtimeDataBytes)
	return reportData
}

// Takes bytes and generate host data that UVM creates at launch of SNP VM (SHA256 hash of arbitrary data).
// It's only useful to create fake attestation report
func GenerateMAAHostData(inputBytes []byte) [HOST_DATA_SIZE]byte {
	inittimeData := sha256.New()
	if inputBytes != nil {
		inittimeData.Write(inputBytes)
	}
	hostData := [HOST_DATA_SIZE]byte{}
	inittimeDataBytes := inittimeData.Sum(nil)
	const sha256len = 32
	if len(inittimeDataBytes) != sha256len {
		panic(fmt.Errorf("length of sha256 hash should be %d bytes, but it is actually %d bytes", sha256len, len(inittimeDataBytes)))
	}
	if sha256len > HOST_DATA_SIZE {
		panic(fmt.Errorf("generated hash is too large for host data. hash length: %d bytes, report host size: %d", sha256len, REPORT_DATA_SIZE))
	}
	copy(hostData[:], inittimeDataBytes)
	return hostData
}

// Attest interacts with maa services to fetch an MAA token
// MAA expects four attributes:
// (A) the attestation report signed by the PSP signing key
// (B) a certificate chain that endorses the signing key of the attestation report
// (C) reference information that provides evidence that the UVM image is genuine.
// (D) inittime data: this is the policy blob that has been hashed by the host OS during the utility
//
//	VM bringup and has been reported by the PSP in the attestation report as HOST DATA
//
// (E) runtime data: for example it may be a wrapping key blob that has been hashed during the attestation report
//
//	retrieval and has been reported by the PSP in the attestation report as REPORT DATA
//
// Note that it uses fake attestation report if it's not running inside SNP VM
func (certState *CertState) Attest(maa MAA, runtimeDataBytes []byte, uvmInformation common.UvmInformation) (string, error) {
	inittimeDataBytes, err := base64.StdEncoding.DecodeString(uvmInformation.EncodedSecurityPolicy)
	if err != nil {
		return "", errors.Wrap(err, "decoding policy from Base64 format failed")
	}
	logrus.Debugf("   inittimeDataBytes:    %v", inittimeDataBytes)

	// Fetch the attestation report

	var reportFetcher AttestationReportFetcher
	if IsSNPVM() {

		reportFetcher, err = NewAttestationReportFetcher()
		if err != nil {
			return "", errors.Wrapf(err, "failed to create attestation report fetcher")
		}
	} else {
		// Use fake attestation report if it's not running inside SNP VM
		hostData := GenerateMAAHostData(inittimeDataBytes)
		reportFetcher = UnsafeNewFakeAttestationReportFetcher(hostData)
	}

	reportData := GenerateMAAReportData(runtimeDataBytes)
	SNPReportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", errors.Wrapf(err, "failed to retrieve attestation report")
	}

	// Retrieve the certificate chain using the chip identifier and platform version
	// fields of the attestation report
	var SNPReport SNPAttestationReport
	if err = SNPReport.DeserializeReport(SNPReportBytes); err != nil {
		return "", errors.Wrapf(err, "failed to deserialize attestation report")
	}

	logrus.Debugf("SNP Report Reported TCB: %d\nCert Chain TCBM Value: %d\n", SNPReport.ReportedTCB, certState.Tcbm)

	// At this point check that the TCB of the cert chain matches that reported so we fail early or
	// fetch fresh certs by other means.
	var vcekCertChain []byte
	if SNPReport.ReportedTCB != certState.Tcbm {
		// TCB values not the same, try refreshing cert cache first
		vcekCertChain, err = certState.RefreshCertChain(SNPReport)
		if err != nil {
			return "", err
		}

		if SNPReport.ReportedTCB != certState.Tcbm {
			// TCB values still don't match, try retrieving the SNP report again
			SNPReportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
			if err != nil {
				return "", errors.Wrapf(err, "failed to retrieve new attestation report")
			}

			if err = SNPReport.DeserializeReport(SNPReportBytes); err != nil {
				return "", errors.Wrapf(err, "failed to deserialize new attestation report")
			}

			// refresh certs again
			vcekCertChain, err = certState.RefreshCertChain(SNPReport)
			if err != nil {
				return "", err
			}

			// if no match after refreshing certs and attestation report, fail
			if SNPReport.ReportedTCB != certState.Tcbm {
				return "", errors.New(fmt.Sprintf("SNP reported TCB value: %d doesn't match Certificate TCB value: %d", SNPReport.ReportedTCB, certState.Tcbm))
			}
		}
	} else {
		certString := uvmInformation.InitialCerts.VcekCert + uvmInformation.InitialCerts.CertificateChain
		vcekCertChain = []byte(certString)
	}

	uvmReferenceInfoBytes, err := base64.StdEncoding.DecodeString(uvmInformation.EncodedUvmReferenceInfo)

	if err != nil {
		return "", errors.Wrap(err, "decoding policy from Base64 format failed")
	}

	// Retrieve the MAA token required by the request's MAA endpoint
	maaToken, err := maa.attest(SNPReportBytes, vcekCertChain, inittimeDataBytes, runtimeDataBytes, uvmReferenceInfoBytes)
	if err != nil || maaToken == "" {
		return "", errors.Wrapf(err, "retrieving MAA token from MAA endpoint failed")
	}

	return maaToken, nil
}
