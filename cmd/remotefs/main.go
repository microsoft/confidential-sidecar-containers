// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/sirupsen/logrus"
)

const ERROR_STRING = `ERROR: Please refer to the documentation for more information on how to use this sidecar
ACI: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/encfs/README.md
Troubleshooting: https://github.com/microsoft/confidential-sidecar-containers/blob/main/examples/encfs/TROUBLESHOOTING.md`

type AzureInfo struct {
	CertFetcher attest.CertFetcher `json:"certcache,omitempty"`
	Identity    common.Identity    `json:"identity,omitempty"`
}

type RemoteFilesystemsInformation struct {
	AzureInfo        AzureInfo         `json:"azure_info"`
	AzureFilesystems []AzureFilesystem `json:"azure_filesystems"`
}

// AzureFilesystem contains information about a filesystem image stored in Azure
// Blob Storage.
type AzureFilesystem struct {
	// This is the URL of the image
	AzureUrl string `json:"azure_url"`
	// This is a private AzureUrl
	AzureUrlPrivate bool `json:"azure_url_private"`
	// This is the path where the filesystem will be exposed in the container.
	MountPoint string `json:"mount_point"`
	// This is the information used by encfs to derive the encryption key of the filesystem
	// if the key being released is a private RSA key
	KeyDerivationBlob common.KeyDerivationBlob `json:"key_derivation,omitempty"`
	// This is the information used by skr to release the encryption key of the filesystem
	KeyBlob common.KeyBlob `json:"key,omitempty"`
	// This is a testing key hexstring encoded to be used against the filesystem. This should
	// be used only for testing.
	RawKeyHexString string `json:"raw_key,omitempty"`
	// This is a flag specifying if this file system is read-write
	ReadWrite bool `json:"read_write,omitempty"`
}

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	base64string := flag.String("base64", "", "base64-encoded json string with all information")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer func() {
			err := file.Close()
			if err != nil {
				logrus.Fatal(err)
			}
		}()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatalf("Failed to parse logLevel: %s\n%s", err, ERROR_STRING)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Infof("Args:")
	logrus.Infof("   Log Level: %s", *logLevel)
	logrus.Infof("   Log File:  %s", *logFile)
	logrus.Debugf("   base64:    %s", *base64string)

	logrus.Info("Creating temporary directory")
	tempDir, err := os.MkdirTemp("", "remotefs")
	if err != nil {
		logrus.Fatalf("Failed to create temp dir: %s", err.Error())
	}
	logrus.Infof("Temporary directory: %s", tempDir)

	// Decode information
	bytes, err := base64.StdEncoding.DecodeString(*base64string)
	if err != nil {
		logrus.Fatalf("Failed to decode base64: %s\n%s", err.Error(), ERROR_STRING)
	}

	info := RemoteFilesystemsInformation{}
	err = json.Unmarshal(bytes, &info)
	if err != nil {
		logrus.Fatalf("Failed to unmarshal base64 string: %s\n%s", err.Error(), ERROR_STRING)
	}

	logrus.Infof("%d filesystems to mount:", len(info.AzureFilesystems))

	// populate missing attributes in KeyBlob
	for i, fs := range info.AzureFilesystems {
		logrus.Infof("  %s -> %s (read-write: %t)", fs.MountPoint, fs.AzureUrl, fs.ReadWrite)
		// KeyBlob only contains the identifier of the key, so we can print it,
		// but we need to ensure we do not print any AKV tokens, if it has any.
		// SafeString() handles that.
		logrus.Debugf("    keyBlob: %s", fs.KeyBlob.SafeString())
		// KeyDerivationBlob contains the salt and label used to derive the key,
		// but the actual HKDF derivation requires the RSA private key, acquired
		// via key release, and so we can safely print it since it won't expose
		// the derived key.
		logrus.Debugf("    KeyDerivationBlob: %+v", fs.KeyDerivationBlob)
		if fs.RawKeyHexString != "" {
			if allowTestingWithRawKey {
				logrus.Debug("    RawKeyHexString provided, using it for testing and skipping skr")
			} else {
				logrus.Warnf("filesystem %s: provided RawKeyHexString will be ignored as this image does not allow testing with raw key input.", fs.MountPoint)
			}
		}
		// set the api versions and the tee type for which the authority will authorize secure key release
		info.AzureFilesystems[i].KeyBlob.AKV.APIVersion = "api-version=7.4"
		info.AzureFilesystems[i].KeyBlob.Authority.APIVersion = "api-version=2020-10-01"
		info.AzureFilesystems[i].KeyBlob.Authority.TEEType = "SevSnpVM"
	}

	err = MountAzureFilesystems(tempDir, info)
	if err != nil {
		logrus.Fatalf("Failed to mount filesystems: %s\n%s", err.Error(), ERROR_STRING)
	}

}
