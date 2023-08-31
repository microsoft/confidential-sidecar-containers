// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !skip_snp_required

// This test requires to be ran inside SNP VM.
// To skip this, you can use `go test ./... -tag skip_snp_required`.

package attest

import (
	"encoding/hex"
	"testing"
)

func TestFetchReport(t *testing.T) {
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
		t.Fatalf("fetching report failed: %v", err)
	}
	expectedByteString := hex.EncodeToString(reportData[:])
	// Confirm `report data` (user provided 64 byte data) is correct
	assertEqual(t, "Check report data", expectedByteString, hex.EncodeToString(reportBytes[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET+REPORT_DATA_SIZE]))
}
