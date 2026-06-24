// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

package attest

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/snppspapi"
)

func NewAttestationReportFetcher() (AttestationReportFetcher, error) {
	// Confirm we are running in an SEV-SNP VM before returning a fetcher.
	isSnp, err := snppspapi.IsSnpMode()
	if err != nil {
		return nil, fmt.Errorf("SnpPspIsSnpMode failed: %w", err)
	}
	if !isSnp {
		return nil, fmt.Errorf("not running in an SEV-SNP VM")
	}

	return &windowsAttestationReportFetcher{}, nil
}

type windowsAttestationReportFetcher struct{}

func (f *windowsAttestationReportFetcher) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	// SNPPSP_API_ATTESTATION_REPORT_SIZE (0x4A0) == ATTESTATION_REPORT_SIZE (1184).
	report, _, err := snppspapi.FetchAttestationReport(reportData)
	if err != nil {
		return nil, fmt.Errorf("SnpPspFetchAttestationReport failed: %w", err)
	}

	reportBytes := report[:]

	if common.GenerateTestData {
		if err := os.WriteFile("snp_report.bin", reportBytes, 0644); err != nil {
			return nil, fmt.Errorf("writing snp report failed: %v", err)
		}
	}

	return reportBytes, nil
}

func (f *windowsAttestationReportFetcher) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}
