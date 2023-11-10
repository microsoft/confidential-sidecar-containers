// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/internal/httpginendpoints"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	server "github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/grpcserver"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/keyprovider"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

// TODO:
// - vcek source is different
// - aci gets security policy and hashes it

func main() {
	azureInfoBase64string := flag.String("base64", "", "optional base64-encoded json string with azure information")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")
	httpPort := flag.String("port", "8080", "Port on which to listen")
	allowTestingMismatchedTCB := flag.Bool("allowTestingMismatchedTCB", false, "For TESTING purposes only. Corrupts the TCB value")
	// NOTE: these 4 input arguments are typically only used in AKS, not ACI
	grpcPort := flag.String("keyprovider_sock", "127.0.0.1:50000", "Port on which the grpc key provider to listen")
	infile := flag.String("infile", "", "The file with its content to be wrapped")
	key_path := flag.String("keypath", "", "The path to the wrapping key")
	outfile := flag.String("outfile", "", "The file to save the wrapped data")

	// for testing mis-matched TCB versions allowTestingWithMismatchedTCB
	// and CorruptedTCB
	CorruptedTCB := "ffffffff"
	// WARNING!!!
	// If the security policy does not control the arguments to this process then
	// this hostname could be set to 0.0.0.0 (an external interface) rather than 127.0.0.1 (visible only
	// within the container group/pod) and so expose the attestation and key release outside of the secure uvm

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
	logrus.Debugf("   Port:          %s", *httpPort)
	logrus.Debugf("   Hostname:      %s", *hostname)
	logrus.Debugf("   azure info:    %s", *azureInfoBase64string)
	logrus.Debugf("   corrupt tcbm:  %t", *allowTestingMismatchedTCB)

	if *infile != "" {
		bytes, err := os.ReadFile(*infile)
		if err != nil {
			log.Fatalf("Can't read input file %v", *infile)
		}
		if *key_path == "" {
			log.Fatalf("The key path is not specified for wrapping")
		}
		if *outfile == "" {
			log.Fatalf("The output file is not specified")
		}

		if _, err := os.Stat(*key_path + "-info.json"); err != nil {
			log.Fatalf("The wrapping key info is not found")
		}

		annotationBytes, e := server.DirectWrap(bytes, *key_path)
		if e != nil {
			log.Fatalf("%v", e)
		}

		outstr := base64.StdEncoding.EncodeToString(annotationBytes)
		if err := os.WriteFile(*outfile, []byte(outstr), 0644); err != nil {
			log.Fatalf("Failed to save the wrapped data to %v", *outfile)
		}
		log.Printf("Success! The wrapped data is saved to %v", *outfile)
		return
	}

	info := server.AzureInformation{}

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

	EncodedUvmInformation, err := common.GetUvmInformation() // from the env.
	if err != nil {
		logrus.Infof("Failed to extract UVM_* environment variables: %s", err.Error())
	}

	if common.ThimCertsAbsent(&EncodedUvmInformation.InitialCerts) {
		logrus.Info("ThimCerts is absent, retrieving THIMCerts from THIM endpoint.")
		thimCerts, err := info.CertFetcher.GetThimCerts("")
		if err != nil {
			logrus.Fatalf("Failed to retrieve thim certs: %s", err.Error())
		}

		EncodedUvmInformation.InitialCerts = *thimCerts
	}

	// See above comment about hostname and risk of breaking confidentiality
	url := *hostname + ":" + *httpPort

	logrus.Trace("Getting initial TCBM value...")
	var tcbm string
	if *allowTestingMismatchedTCB {
		// NOTE: this should only be used for testing purposes
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
	go setupServer(&certState, &info.Identity, &EncodedUvmInformation, url)

	lis, err := net.Listen("tcp", *grpcPort)
	if err != nil {
		log.Fatalf("failed to listen on port %v: %v", *grpcPort, err)
	}
	log.Printf("Listening on port %v", *grpcPort)
	//start grpc server
	s := grpc.NewServer()
	server := server.Server{ServerCertState: &certState, EncodedUvmInformation: &EncodedUvmInformation, Azure_info: &info}
	keyprovider.RegisterKeyProviderServiceServer(s, &server)
	reflection.Register(s)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start GRPC server: %v", err)
	}
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
