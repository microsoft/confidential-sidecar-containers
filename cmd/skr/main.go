// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/internal/httpginendpoints"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AzureInformation struct {
	// Endpoint of the certificate cache service from which
	// the certificate chain endorsing hardware attestations
	// can be retrieved. This is optional only when the container
	// will expose attest/maa and key/release APIs.
	CertFetcher attest.CertFetcher `json:"certcache,omitempty"`
	// Identifier of the managed identity to be used
	// for authenticating with AKV. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	azureInfoBase64string := flag.String("base64", "", "optional base64-encoded json string with azure information")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")
	port := flag.String("port", "8080", "Port on which to listen")
	allowTestingMismatchedTCB := flag.Bool("allowTestingMismatchedTCB", false, "For TESTING purposes only. Corrupts the TCB value")

	// for testing mis-matched TCB versions allowTestingWithMismatchedTCB
	// and CorruptedTCB
	CorruptedTCB := "ffffffff"
	// WARNING!!!
	// If the security policy does not control the arguments to this process then
	// this hostname could be set to 0.0.0.0 (an external interface) rather than 127.0.0.1 (visible only
	// witin the container group/pod)and so expose the attestation and key release outside of the secure uvm

	// Leaving this line here, as a comment, to aid debugging.
	// hostname := flag.String("hostname", "localhost", "address on which to listen (dangerous)")
	localhost := "localhost"
	hostname := &localhost

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Infof("Args:")
	logrus.Infof("   Log Level:     %s", *logLevel)
	logrus.Infof("   Log File:      %s", *logFile)
	logrus.Debugf("   Port:          %s", *port)
	logrus.Debugf("   Hostname:      %s", *hostname)
	logrus.Debugf("   azure info:    %s", *azureInfoBase64string)
	logrus.Debugf("   corrupt tcbm:  %t", *allowTestingMismatchedTCB)

	EncodedUvmInformation, err := common.GetUvmInformation() // from the env.
	if err != nil {
		logrus.Fatalf("Failed to extract UVM_* environment variables: %s", err.Error())
	}

	info := AzureInformation{}

	// Decode base64 attestation information only if it s not empty
	logrus.Info("Decoding base64 attestation information if not empty...")
	if *azureInfoBase64string != "" {
		bytes, err := base64.StdEncoding.DecodeString(*azureInfoBase64string)
		if err != nil {
			logrus.Fatalf("Failed to decode base64 attestation info: %s", err.Error())
		}

		err = json.Unmarshal(bytes, &info)
		if err != nil {
			logrus.Fatalf("Failed to unmarshal attestion info json into AzureInformation: %s", err.Error())
		}
	}

	// See above comment about hostname and risk of breaking confidentiality
	url := *hostname + ":" + *port

	logrus.Trace("Getting initial TCBM value...")
	var tcbm string
	if *allowTestingMismatchedTCB {
		logrus.Debugf("setting tcbm to CorruptedTCB value: %s\n", CorruptedTCB)
		tcbm = CorruptedTCB
	} else {
		logrus.Debugf("setting tcbm to EncodedUvmInformation.InitialCerts.Tcbm value: %s\n", EncodedUvmInformation.InitialCerts.Tcbm)
		tcbm = EncodedUvmInformation.InitialCerts.Tcbm
	}

	thimTcbm, err := strconv.ParseUint(tcbm, 16, 64)
	if err != nil {
		logrus.Fatal("Unable to convert intial TCBM to a uint64")
	}

	certState := attest.CertState{
		CertFetcher: info.CertFetcher,
		Tcbm:        thimTcbm,
	}

	logrus.Info("Starting HTTP server...")
	setupServer(&certState, &info.Identity, &EncodedUvmInformation, url)
}

func setupServer(certState *attest.CertState, identity *common.Identity, uvmInfo *common.UvmInformation, url string) {
	certString := uvmInfo.InitialCerts.VcekCert + uvmInfo.InitialCerts.CertificateChain
	logrus.Debugf("Setting security policy to %s", uvmInfo.EncodedSecurityPolicy)
	logrus.Debugf("Setting uvm reference to %s", uvmInfo.EncodedUvmReferenceInfo)
	logrus.Debugf("Setting platform certs to %s", certString)

	server := gin.Default()
	server.Use(httpginendpoints.RegisterGlobalStates(certState, identity, uvmInfo))
	server.GET("/status", httpginendpoints.GetStatus)
	server.POST("/attest/raw", httpginendpoints.PostRawAttest)
	server.POST("/attest/maa", httpginendpoints.PostMAAAttest)
	server.POST("/key/release", httpginendpoints.PostKeyRelease)
	httpginendpoints.SetServerReady()
	server.Run(url)
}
