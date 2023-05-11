package common

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testDataDir = flag.String("testdata-dir", "test_data/", "Path to testdata directory")
)

func TestGetPlatformCertificateFromEnvironment(t *testing.T) {
	flag.Parse()
	testDataHostAmdCertificate := filepath.Join(*testDataDir, "host_amd_certificate_env")
	certificate, err := os.ReadFile(testDataHostAmdCertificate)
	if err != nil {
		t.Fatalf("Could not open file %s", testDataHostAmdCertificate)
	}

	// Valid
	_, err = ParseTHIMCerts(string(certificate))
	if err != nil {
		t.Fatalf("Could not parse ACI certificate: %s", err)
	}

	// Empty
	_, err = ParseTHIMCerts("")
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse ACI certificate: %s", err)
	}

	// Invalid base64
	_, err = ParseTHIMCerts(string(certificate[:len(certificate)-1]))
	if !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatalf("Could not parse ACI certificate: %s", err)
	}

	// Invalid JSON
	_, err = ParseTHIMCerts(string(certificate[:len(certificate)-4]))
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse ACI certificate: %s", err)
	}
}
