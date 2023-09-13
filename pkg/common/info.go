// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"strconv"

	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

func ParseTHIMCertsFromString(base64EncodedHostCertsFromTHIM string) (THIMCerts, error) {
	certificatesRaw, err := base64.StdEncoding.DecodeString(base64EncodedHostCertsFromTHIM)
	if err != nil {
		return THIMCerts{}, errors.Wrapf(err, "base64 decoding platform certs failed")
	}

	certificates := THIMCerts{}
	err = json.Unmarshal([]byte(certificatesRaw), &certificates)
	if err != nil {
		return THIMCerts{}, errors.Wrapf(err, "failed to unmarshal THIM certificate")
	}
	return certificates, nil
}

func ParseTHIMCertsFromByte(base64EncodedHostCertsFromTHIM []byte) (THIMCerts, error) {
	certificates := THIMCerts{}
	err := json.Unmarshal(base64EncodedHostCertsFromTHIM, &certificates)
	if err != nil {
		return THIMCerts{}, errors.Wrapf(err, "failed to unmarshal THIM certificate")
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

func GetUvmSecurityCtxDir() (string, error) {
	securityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	if securityContextDir == "" {
		return "", errors.New("UVM_SECURITY_CONTEXT_DIR not set")
	}
	return securityContextDir, nil
}

func GetUvmInformation() (UvmInformation, error) {
	_, err := GetUvmSecurityCtxDir()
	if err != nil {
		return GetUvmInformationFromEnv()
	} else {
		return GetUvmInformationFromFiles()
	}
}

func GetUvmInformationFromEnv() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		os.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		var err error
		encodedUvmInformation.InitialCerts, err = ParseTHIMCertsFromString(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		os.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		os.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
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

	securityContextDir, err := GetUvmSecurityCtxDir()
	if err != nil {
		return encodedUvmInformation, err
	}

	encodedHostCertsFromTHIM, err := readSecurityContextFile(securityContextDir, HostAMDCertFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading host amd cert failed")
	}

	if GenerateTestData {
		os.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
	}

	if encodedHostCertsFromTHIM != "" {
		var err error
		encodedUvmInformation.InitialCerts, err = ParseTHIMCertsFromString(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
	}

	encodedUvmInformation.EncodedSecurityPolicy, err = readSecurityContextFile(securityContextDir, PolicyFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading security policy failed")
	}

	encodedUvmInformation.EncodedUvmReferenceInfo, err = GetReferenceInfoFile(securityContextDir, ReferenceInfoFilename)
	if err != nil {
		return encodedUvmInformation, err
	}

	if GenerateTestData {
		os.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		os.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
	}

	return encodedUvmInformation, nil
}

func GetReferenceInfoFile(securityContextDir string, ReferenceInfoFilename string) (string, error) {
	encodedUvmReferenceInfo, err := readSecurityContextFile(securityContextDir, ReferenceInfoFilename)
	if err != nil {
		return encodedUvmReferenceInfo, errors.Wrapf(err, "reading uvm reference info failed")
	}
	return encodedUvmReferenceInfo, nil
}

func GetUvmInformationAASP(UvmInfo *UvmInformation) {
	securityContextDir, err := GetUvmSecurityCtxDir()
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	UvmInfo.EncodedUvmReferenceInfo, err = GetReferenceInfoFile(securityContextDir, ReferenceInfoFilename)
	if err != nil {
		logrus.Fatalf(err.Error())
	}

	if GenerateTestData {
		os.WriteFile("uvm_reference_info.base64", []byte(UvmInfo.EncodedUvmReferenceInfo), 0644)
	}

	if GenerateTestData {
		THIMCertsBytes, _ := json.Marshal(UvmInfo.InitialCerts)
		certificatesRaw := base64.StdEncoding.EncodeToString(THIMCertsBytes)
		os.WriteFile("uvm_host_amd_certificate.base64", []byte(certificatesRaw), 0644)
	}
}
