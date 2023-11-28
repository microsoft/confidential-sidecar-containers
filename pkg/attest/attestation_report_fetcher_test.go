// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"encoding/hex"
	"testing"
)

func assertEqual[T comparable](t *testing.T, description string, expect T, actual T) {
	if expect != actual {
		t.Fatalf("%s: Expected %v, but got %v", description, expect, actual)
	}
}

func TestFetchFakeReport(t *testing.T) {
	// Report data for test
	reportData := [REPORT_DATA_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportData[i] = byte(i)
	}

	hostData := [HOST_DATA_SIZE]byte{}
	for i := 0; i < HOST_DATA_SIZE; i++ {
		hostData[i] = byte(i)
	}

	reportFetcher := UnsafeNewFakeAttestationReportFetcher(hostData)
	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		t.Fatalf("Fetching report failed: %v", err)
	}
	expectedReportDataByteString := hex.EncodeToString(reportData[:])
	// Confirm `report data` (user provided 64 byte data) is correct
	assertEqual(t, "Check report data", expectedReportDataByteString, hex.EncodeToString(reportBytes[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET+REPORT_DATA_SIZE]))
	expectedHostDataByteString := hex.EncodeToString(hostData[:])
	// Confirm `report data` (user provided 64 byte data) is correct
	assertEqual(t, "Check host data", expectedHostDataByteString, hex.EncodeToString(reportBytes[HOST_DATA_OFFSET:HOST_DATA_OFFSET+HOST_DATA_SIZE]))
}
