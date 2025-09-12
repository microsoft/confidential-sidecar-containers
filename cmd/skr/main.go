// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/internal/httpginendpoints"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	server "github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/grpcserver"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/key_provider"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

const ConfidentialSkrContainerIdentifier = "ConfidentialSkrContainer"

func main() {
	azureInfoBase64string := flag.String("base64", "", "optional base64-encoded json string with azure information")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")
	port := flag.String("port", "8080", "Port on which to listen")
	allowTestingMismatchedTCB := flag.Bool("allowTestingMismatchedTCB", false, "For TESTING purposes only. Corrupts the TCB value")
	// NOTE: these 4 input arguments are typically only used in AKS, not ACI
	serverType := flag.String("server_type", "http", "Choose whether to use http or grpc for the server type")
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
		logrus.Fatalf("Failed to parse logLevel: %s\n%s", err, skr.ERROR_STRING)
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

	if *infile != "" {
		bytes, err := os.ReadFile(*infile)
		if err != nil {
			logrus.Fatalf("Can't read input file %v\n%s", *infile, skr.ERROR_STRING)
		}
		if *key_path == "" {
			logrus.Fatalf("The key path is not specified for wrapping\n%s", skr.ERROR_STRING)
		}
		if *outfile == "" {
			logrus.Fatalf("The output file is not specified\n%s", skr.ERROR_STRING)
		}

		if _, err := os.Stat(*key_path + "-info.json"); err != nil {
			logrus.Fatalf("The wrapping key info is not found\n%s", skr.ERROR_STRING)
		}

		annotationBytes, err := server.DirectWrap(bytes, *key_path)
		if err != nil {
			logrus.Fatalf("%v\n%s", err, skr.ERROR_STRING)
		}

		outstr := base64.StdEncoding.EncodeToString(annotationBytes)
		if err := os.WriteFile(*outfile, []byte(outstr), 0644); err != nil {
			logrus.Fatalf("Failed to save the wrapped data to %v\n%s", *outfile, skr.ERROR_STRING)
		}
		logrus.Printf("Success! The wrapped data is saved to %v", *outfile)
		return
	}

	info := server.AzureInformation{}

	// Decode base64 attestation information only if it s not empty
	logrus.Info("Decoding base64 attestation information if not empty...")
	if *azureInfoBase64string != "" {
		bytes, err := base64.StdEncoding.DecodeString(*azureInfoBase64string)
		if err != nil {
			logrus.Fatalf("Failed to decode base64 attestation info: %s\n%s", err.Error(), skr.ERROR_STRING)
		}

		err = json.Unmarshal(bytes, &info)
		if err != nil {
			logrus.Fatalf("Failed to unmarshal attestion info json into AzureInformation: %s\n%s", err.Error(), skr.ERROR_STRING)
		}
	}

	common.MAAClientUserAgent = info.MAAConfig.UserAgent
	if common.MAAClientUserAgent == "" {
		logrus.Info("Default MAA User-Agent not provided in AzureInfo blob. Getting a managed identity token to construct a default value...")

		// we fetch the default user agent (i.e. the subscription ID) in a
		// separate goroutine to not delay server startup - acquiring a token
		// can take 1-2 seconds, and longer if the request fails and we retry.

		// Sets a default MAA user agent indicating the request is from this
		// sidecar immediately, before we have the subscription ID.
		common.MAAClientUserAgent = ConfidentialSkrContainerIdentifier

		// Assigning to / reading from a pointer in Go is atomic
		identity := info.Identity // Make a copy
		go func() {
			ua := getDefaultClientIdentifier(identity)
			common.MAAClientUserAgent = ua
			logrus.Infof("Successfully fetched token, setting default MAA User-Agent to: %s", ua)
		}()
	} else {
		logrus.Infof("Using provided string %s as User-Agent for request to MAA", common.MAAClientUserAgent)
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
	url := *hostname + ":" + *port

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
		logrus.Fatal("Unable to convert initial TCBM to a uint64")
	}

	certState := attest.CertState{
		CertFetcher: info.CertFetcher,
		Tcbm:        thimTcbm,
	}

	// default server is http, can optionally use grpc
	if *serverType == "grpc" {
		lis, err := net.Listen("tcp", url)
		if err != nil {
			logrus.Fatalf("failed to listen on port %v: %v\n%s", *port, err, skr.ERROR_STRING)
		}
		logrus.Printf("Listening on port %v", *port)
		// start grpc server
		s := grpc.NewServer()
		server := server.Server{ServerCertState: &certState, EncodedUvmInformation: &EncodedUvmInformation, Azure_info: &info}
		key_provider.RegisterKeyProviderServiceServer(s, &server)
		reflection.Register(s)
		logrus.Printf("server listening at %v", lis.Addr())
		if err := s.Serve(lis); err != nil {
			logrus.Fatalf("failed to start GRPC server: %v\n%s", err, skr.ERROR_STRING)
		}
	} else {
		logrus.Info("Starting HTTP server...")
		setupServer(&certState, &info.Identity, &EncodedUvmInformation, url)
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
	server.POST("/attest/combined", httpginendpoints.PostCombinedAttest) // fetches uvm reference info, certs and attestation report in a form suitable for the Ad Selection API KMS
	server.POST("/attest/maa", httpginendpoints.PostMAAAttest)
	server.POST("/key/release", httpginendpoints.PostKeyRelease)
	httpginendpoints.SetServerReady()
	err := server.Run(url)
	if err != nil {
		logrus.Fatalf("Failed to start HTTP server: %v\n%s", err, skr.ERROR_STRING)
	}
}

// Get a string that can be used as a User-Agent, or other places where we need
// to identify this client. (Used when a custom one is not provided by the user)
func getDefaultClientIdentifier(identity common.Identity) string {
	// We're getting a token in order to extract the subscription or client ID,
	// not for any actual access. However, in order to get a token we have to
	// specify a resource, and so we use keyvault in this case.
	token, err := skr.GetAccessTokenForKeyvault(false, identity)
	if err != nil {
		logrus.Errorf("Failed to get token for key vault from managed identity: %v", err)
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		logrus.Errorf("acquired token is not a JWT")
		return ""
	}
	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		logrus.Errorf("failed to decode payload from acquired token: %v", err)
		return ""
	}
	var payload map[string]interface{}
	err = json.Unmarshal(decodedPayload, &payload)
	if err != nil {
		logrus.Errorf("failed to unmarshal payload from acquired token: %v", err)
		return ""
	}
	rid, ok := payload["xms_az_rid"].(string)
	if !ok || rid == "" {
		logrus.Debugf("No xms_az_rid in token - not a managed identity token, using client id instead")
		appid, ok := payload["appid"].(string)
		if !ok || appid == "" {
			logrus.Errorf("No appid in token - cannot construct default MAA User-Agent")
			return ""
		}
		return fmt.Sprintf("%s client_id=%s", ConfidentialSkrContainerIdentifier, appid)
	}
	rid_parts := strings.Split(rid, "/")
	// 	/subscriptions/.../...
	if len(rid_parts) >= 3 && rid_parts[1] == "subscriptions" {
		subscription_id := rid_parts[2]
		return fmt.Sprintf("%s subscription_id=%s", ConfidentialSkrContainerIdentifier, subscription_id)
	} else {
		logrus.Errorf("Invalid Azure resource ID in xms_az_rid - cannot construct default MAA User-Agent")
		return ""
	}
}
