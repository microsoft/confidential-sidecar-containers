// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"

	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Set to true to regenerate test files at every request.
// Also useful to debug the various steps, especially encoding
// to the correct base64url encoding.

const GenerateTestData = false

// Information supplied by the UVM specific to running Pod

type UvmInformation struct {
	EncodedSecurityPolicy   string // customer security policy
	CertChain               string // platform certificates for the actual physical host, ascii PEM
	EncodedUvmReferenceInfo string // endorsements for the particular UVM image
}

// format of the json provided to the UVM by hcsshim. Comes fro the THIM endpoint
// and is a base64 encoded json string

type THIMCerts struct {
	VcekCert         string `json:"vcekCert"`
	Tcbm             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

func THIMtoPEM(encodedHostCertsFromTHIM string) (string, error) {
	hostCertsFromTHIM, err := base64.StdEncoding.DecodeString(encodedHostCertsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.json", hostCertsFromTHIM, 0644)
	}

	var certsFromTHIM THIMCerts
	err = json.Unmarshal(hostCertsFromTHIM, &certsFromTHIM)
	if err != nil {
		return "", errors.Wrapf(err, "json unmarshal platform certs failed")
	}

	certsString := certsFromTHIM.VcekCert + certsFromTHIM.CertificateChain

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.pem", []byte(certsString), 0644)
	}

	logrus.Debugf("certsFromTHIM:\n\n%s\n\n", certsString)

	return certsString, nil
}

// Late in Public Preview, we made a change to pass the UVM information
// via files instead of environment variables.
// This code detects which method is being used and calls the appropriate
// function to get the UVM information.

// The environment variable scheme will go away by "General Availability"
// but we handle both to decouple this code and the hcsshim/gcs code.

// Matching PR https://github.com/microsoft/hcsshim/pull/1708

func GetUvmInfomation() (UvmInformation, error) {
	securityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	if securityContextDir != "" {
		return GetUvmInfomationFromFiles()
	} else {
		return GetUvmInfomationFromEnv()
	}
}

func GetUvmInfomationFromEnv() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation
	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		ioutil.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		certChain, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.CertChain = certChain
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

func GetUvmInfomationFromFiles() (UvmInformation, error) {
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
		certChain, err := THIMtoPEM(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
		encodedUvmInformation.CertChain = certChain
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
