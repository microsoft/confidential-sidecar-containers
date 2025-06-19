// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
		return thimTcbm, errors.Wrapf(err, "Unable to convert TCBM from THIM certificates %s to a uint64", thimCerts.Tcbm)
	}

	return thimTcbm, nil
}

type UvmInformation struct {
	EncodedSecurityPolicy   string    // base64 customer security policy
	InitialCerts            THIMCerts // platform certificates for the actual physical host
	EncodedUvmReferenceInfo string    // base64 encoded endorsements for the particular UVM image
}

// this will always be set in ACI by the contol plane and is optionally set in K8s.  Need to
// use a default if the customer does not set
const uvmSecurityCtxDirDefault = "/opt/confidential-containers/share/kata-containers"

// Late in Public Preview, we made a change to pass the UVM information
// via files instead of environment variables.
// This code detects which method is being used and calls the appropriate
// function to get the UVM information.

// The environment variable scheme will go away by "General Availability"
// but we handle both to decouple this code and the hcsshim/gcs code.

// Matching PR https://github.com/microsoft/hcsshim/pull/1708

func GetUvmSecurityCtxDir() (string, error) {
	securityContextDir := os.Getenv("UVM_SECURITY_CONTEXT_DIR")
	// no UVM_SECURITY_CONTEXT_DIR set, so iterate through the root directory
	if securityContextDir == "" {
		files, err := os.ReadDir("/")
		if err != nil {
			return "", err
		}
		for _, file := range files {
			if strings.Contains(file.Name(), "security-context-") {
				// found the security context dir
				securityContextDir = filepath.Join("/", file.Name())
				break
			}
		}
	}
	// security context dir not found in root, must be running in AKS
	if securityContextDir == "" {
		logrus.Debugf("Running in Confidential AKS. Using system default security context directory: %q", uvmSecurityCtxDirDefault)
		securityContextDir = uvmSecurityCtxDirDefault
	} else {
		logrus.Infof("Running in Confidential ACI. Using security context directory: %s", securityContextDir)
	}
	return securityContextDir, nil
}

func GetUvmInformation() (UvmInformation, error) {
	contextDir, err := GetUvmSecurityCtxDir()
	var info UvmInformation
	if len(contextDir) > 0 {
		info, err = GetUvmInformationFromFiles()
		if err != nil {
			logrus.Debugf("getting UVM information from directory %q failed. %s", contextDir, err)
		}
	}
	if len(info.EncodedUvmReferenceInfo) == 0 {
		info, err = GetUvmInformationFromEnv()
	}
	return info, err
}

func GetUvmInformationFromEnv() (UvmInformation, error) {
	var encodedUvmInformation UvmInformation
	var err error

	encodedHostCertsFromTHIM := os.Getenv("UVM_HOST_AMD_CERTIFICATE")

	if GenerateTestData {
		err = os.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing host amd cert failed")
		}
	}

	if encodedHostCertsFromTHIM != "" {
		encodedUvmInformation.InitialCerts, err = ParseTHIMCertsFromString(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "parsing host amd cert failed")
		}
	}
	encodedUvmInformation.EncodedSecurityPolicy = os.Getenv("UVM_SECURITY_POLICY")
	encodedUvmInformation.EncodedUvmReferenceInfo = os.Getenv("UVM_REFERENCE_INFO")

	if GenerateTestData {
		err = os.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing security policy failed")
		}
		err = os.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing uvm reference info failed")
		}
	}

	return encodedUvmInformation, err
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

	encodedUvmInformation.EncodedUvmReferenceInfo, err = GetReferenceInfoFile(securityContextDir, ReferenceInfoFilename)
	if err != nil {
		return encodedUvmInformation, err
	}

	if GenerateTestData {
		err = os.WriteFile("uvm_security_policy.base64", []byte(encodedUvmInformation.EncodedSecurityPolicy), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing security policy failed")
		}
		err = os.WriteFile("uvm_reference_info.base64", []byte(encodedUvmInformation.EncodedUvmReferenceInfo), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing uvm reference info failed")
		}
	}

	encodedHostCertsFromTHIM, err := readSecurityContextFile(securityContextDir, HostAMDCertFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading host amd cert failed")
	}

	if GenerateTestData {
		err = os.WriteFile("uvm_host_amd_certificate.base64", []byte(encodedHostCertsFromTHIM), 0644)
		if err != nil {
			return encodedUvmInformation, errors.Wrapf(err, "writing host amd cert failed")
		}
	}

	if encodedHostCertsFromTHIM != "" {
		encodedUvmInformation.InitialCerts, err = ParseTHIMCertsFromString(encodedHostCertsFromTHIM)
		if err != nil {
			return encodedUvmInformation, err
		}
	}

	encodedUvmInformation.EncodedSecurityPolicy, err = readSecurityContextFile(securityContextDir, PolicyFilename)
	if err != nil {
		return encodedUvmInformation, errors.Wrapf(err, "reading security policy failed")
	}

	return encodedUvmInformation, err
}

func GetReferenceInfoFile(securityContextDir string, referenceInfoFilename string) (string, error) {
	encodedUvmReferenceInfo, err := readSecurityContextFile(securityContextDir, referenceInfoFilename)
	if err != nil {
		return encodedUvmReferenceInfo, errors.Wrapf(err, "reading uvm reference info failed")
	}
	return encodedUvmReferenceInfo, nil
}

func ThimCertsAbsent(thim *THIMCerts) bool {
	return len(thim.VcekCert) == 0 && len(thim.CertificateChain) == 0
}
