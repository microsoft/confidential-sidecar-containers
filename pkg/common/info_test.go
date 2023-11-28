package common

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testDataDir = flag.String("testdata-dir", "test_security_context/", "Path to 'security-context-*' directory for test")
)

func Test_ParseTHIMCerts(t *testing.T) {
	flag.Parse()
	testDataHostAmdCertificate := filepath.Join(*testDataDir, "host-amd-cert-base64")
	certificate, err := os.ReadFile(testDataHostAmdCertificate)
	if err != nil {
		t.Fatalf("Could not open file %s", testDataHostAmdCertificate)
	}

	// Valid
	ce, err := ParseTHIMCertsFromString(string(certificate))
	if err != nil {
		t.Fatalf("Could not parse THIM certificate: %s", err)
	}
	log.Printf("%#v\n", ce)

	// Empty
	_, err = ParseTHIMCertsFromString("")
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse THIM certificate: %s", err)
	}

	// Invalid base64
	_, err = ParseTHIMCertsFromString(string(certificate[:len(certificate)-1]))
	if !strings.Contains(err.Error(), "illegal base64 data") {
		t.Fatalf("Could not parse THIM certificate: %s", err)
	}

	// Invalid JSON
	_, err = ParseTHIMCertsFromString(string(certificate[:len(certificate)-4]))
	if !strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("Could not parse THIM certificate: %s", err)
	}
}

func Test_GetUvmInformation(t *testing.T) {
	currentSecurityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	os.Setenv("UVM_SECURITY_CONTEXT_DIR", "test_security_context")
	defer os.Setenv("UVM_SECURITY_CONTEXT_DIR", currentSecurityContextDir)
	uvmInfo, err := GetUvmInformation()
	if err != nil {
		t.Fatalf("Could not get UVM information")
	}

	if len(uvmInfo.EncodedUvmReferenceInfo) == 0 {
		t.Fatalf("UVM reference info is empty")
	}

	_, err = base64.StdEncoding.DecodeString(uvmInfo.EncodedUvmReferenceInfo)
	if err != nil {
		t.Fatalf("Failed to decode base64 encoded UVM reference info: %s", err)
	}

	if len(uvmInfo.EncodedSecurityPolicy) == 0 {
		t.Fatalf("Security policy is empty")
	}

	_, err = base64.StdEncoding.DecodeString(uvmInfo.EncodedSecurityPolicy)
	if err != nil {
		t.Fatalf("Failed to decode base64 encoded security policy: %s", err)
	}
}
