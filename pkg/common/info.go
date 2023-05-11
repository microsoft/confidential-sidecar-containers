// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"

	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

// format of the json provided to the UVM by hcsshim. Comes from the THIM endpoint
// and is a base64 encoded json string
type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func ParseTHIMCerts(base64EncodedHostCertsFromTHIM string) (THIMCerts, error) {
	certificatesRaw, err := base64.StdEncoding.DecodeString(base64EncodedHostCertsFromTHIM)
	if err != nil {
		return THIMCerts{}, fmt.Errorf("Failed to decode ACI certificates: %s", err)
	}

	certificates := THIMCerts{}
	err = json.Unmarshal([]byte(certificatesRaw), &certificates)
	if err != nil {
		return THIMCerts{}, fmt.Errorf("Failed to unmarshal JSON ACI certificates: %s", err)
	}
	return certificates, nil
}

func ConcatenateCerts(thimCerts THIMCerts) []byte {
	return []byte(thimCerts.VcekCert + thimCerts.CertificateChain)
}

func ParseTHIMTCBM(thimCerts THIMCerts) (uint64, error) {
	thimTcbm, err := strconv.ParseUint(thimCerts.Tcbm, 16, 64)
	if err != nil {
		return thimTcbm, errors.Wrap(err, "Unable to convert TCBM from THIM certificates to a uint64")
	}

	return thimTcbm, nil
}

type UvmInformation struct {
	EncodedSecurityPolicy   string    // base64 customer security policy
	InitialCerts            THIMCerts // platform certificates for the actual physical host
	EncodedUvmReferenceInfo string    // base64 encoded endorsements for the particular UVM image
}

// Late in Public Preview, we made a change to pass the UVM information
// via files instead of environment variables.
// This code detects which method is being used and calls the appropriate
// function to get the UVM information.

// The environment variable scheme will go away by "General Availability"
// but we handle both to decouple this code and the hcsshim/gcs code.

// Matching PR https://github.com/microsoft/hcsshim/pull/1708

func GetUvmInformation() (UvmInformation, error) {
	securityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	if securityContextDir != "" {
		return GetUvmInformationFromFiles()
	} else {
		return GetUvmInformationFromEnv()
	}
}

func GetUvmInformationFromEnv() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		var err error
		encodedUvmInformation.InitialCerts, err = ParseTHIMCerts(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}

// From hcsshim pkg/securitypolicy/securitypolicy.go

const (
	SecurityContextDirTemplate = "security-context-*"
	PolicyFilename             = "security-policy-base64"
	HostAMDCertFilename        = "host-amd-cert-base64"
	ReferenceInfoFilename      = "reference-info-base64"
)

func readSecurityContextFile(dir string, filename string) (string, error) {
	targetFilename := filepath.Join(dir, filename)
	blob, err := os.ReadFile(targetFilename)
	if err != nil {
		return "", err
	}
	return string(blob), nil
}

func GetUvmInformationFromFiles() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation

	securityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	if securityContextDir == "" {
		return encodedUvmInformation, errors.New("UVM_SECURITY_CONTEXT_DIR not set")
	}

	encodedHostCertsFromTHIM, err := readSecurityContextFile(securityContextDir, HostAMDCertFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading host amd cert failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		var err error
		encodedUvmInformation.InitialCerts, err = ParseTHIMCerts(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
	}

	encodedUvmInformation.EncodedSecurityPolicy, err = readSecurityContextFile(securityContextDir, PolicyFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading security policy failed")
	}

	encodedUvmInformation.EncodedUvmReferenceInfo, err = readSecurityContextFile(securityContextDir, ReferenceInfoFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading uvm reference info failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		ioutil.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}
