// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !skip_snp_required

// This test requires to be ran inside SNP VM.
// To skip this, you can use `go test ./... -tag skip_snp_required`.

package attest

import (
	_ "embed"
	"testing"
)

func TestCertFetcherWithRealAttestationReport(t *testing.T) {
	// Report data for test
	reportData := [REPORT_DATA_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportData[i] = byte(i)
	}

	reportFetcher, err := NewAttestationReportFetcher()
	if err != nil {
		t.Fatalf("attestation-container is not running in SNP enabled VM")
	}

	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		t.Fatalf("failed to fetch report for test")
	}
	var TestSNPReport SNPAttestationReport
	if err := TestSNPReport.DeserializeReport(reportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ValidChipID := TestSNPReport.ChipID
	ValidPlatformVersion := TestSNPReport.PlatformVersion

	type testcase struct {
		name string

		certFetcher CertFetcher

		chipID          string
		platformVersion uint64

		expectedError error
		expectErr     bool
	}

	testcases := []*testcase{
		// CertFetcher_Success passes the testing if it does not receive an error and the certchain mathces the expected content
		{
			name:            "CertFetcher_Success_AMD",
			certFetcher:     DefaultAMDMilanCertFetcherNew(),
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   nil,
			expectErr:       false,
		},
		// CertFetcher_DefaultAzureCertFetcherNew_Success passes the testing if it does not receive an error and the certchain mathces the expected content
		{
			name:            "CertFetcher_DefaultAzureCertFetcherNew_Success",
			certFetcher:     DefaultAzureCertFetcherNew(),
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   nil,
			expectErr:       false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			certchain, _, err := tc.certFetcher.GetCertChain(tc.chipID, tc.platformVersion)

			if tc.expectErr {
				if err == nil {
					t.Fatal("expected err got nil")
				}
				if err.Error() != tc.expectedError.Error() {
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect err got %q", err.Error())
				}
				if len(certchain) == 0 {
					t.Fatalf("got empty cert chain")
				}
			}
		})
	}
}
