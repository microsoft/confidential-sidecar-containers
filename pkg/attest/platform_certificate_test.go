package attest

import (
	"fmt"
	"testing"
)

func getReportedTCBAndChipID(t *testing.T) ([]byte, []byte) {
	// Get attestation report to get chip ID and reported TCB
	// Report data for test
	reportData := [REPORT_DATA_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportData[i] = byte(i)
	}

	reportFetcher := AttestationReportFetcherNew()
	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		t.Fatalf("Fetching report failed: %v", err)
	}
	reportedTCBBytes := reportBytes[REPORTED_TCB_OFFSET : REPORTED_TCB_OFFSET+REPORTED_TCB_SIZE]
	chipIDBytes := reportBytes[CHIP_ID_OFFSET : CHIP_ID_OFFSET+CHIP_ID_SIZE]
	return reportedTCBBytes, chipIDBytes
}

func TestFetchPlatformCertificateFromAzure(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	certificates, err := FetchPlatformCertificate("Azure", reportedTCBBytes, chipIDBytes)
	if err != nil || len(certificates) == 0 {
		t.Fatalf("Fetching platform certificate failed: %s", err)
	}
}

func TestFetchPlatformCertificateFromAMD(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	certificates, err := FetchPlatformCertificate("AMD", reportedTCBBytes, chipIDBytes)
	if err != nil || len(certificates) == 0 {
		t.Fatalf("Fetching platform certificate failed: %s", err)
	}
}

func TestInvalidServer(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	server := "Invalid Server Type"
	_, err := FetchPlatformCertificate(server, reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("invalid platform certificate server: %s", server) {
		t.Fatalf("Should return error for invalid server")
	}
}

func TestInvalidReportedTCBBytes(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	reportedTCBBytes = []byte{}
	_, err := FetchPlatformCertificate("Azure", reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("Length of reportedTCBBytes should be %d", REPORTED_TCB_SIZE) {
		t.Fatalf("Should return error for invalid length of reportedTCBBytes")
	}
}

func TestInvalidChipID(t *testing.T) {
	reportedTCBBytes, chipIDBytes := getReportedTCBAndChipID(t)
	chipIDBytes = []byte{}
	_, err := FetchPlatformCertificate("Azure", reportedTCBBytes, chipIDBytes)
	if err.Error() != fmt.Sprintf("Length of chipIDBytes should be %d", CHIP_ID_SIZE) {
		t.Fatalf("Should return error for invalid length of chipIDBytes")
	}
}
