// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"

	pb "github.com/Microsoft/confidential-sidecar-containers/cmd/attestation-container/protobuf"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sirupsen/logrus"
)

var (
	socketAddress             = flag.String("socket-address", "/tmp/attestation-container.sock", "The socket address of Unix domain socket (UDS)")
	platformCertificateServer = flag.String("platform-certificate-server", "", "Server to fetch platform certificate. If set, certificates contained in security context directory are ignored. Value is either 'Azure' or 'AMD'")
	insecureVirtual           = flag.Bool("insecure-virtual", false, "If set, dummy attestation is returned (INSECURE: do not use in production)")
	logLevel                  = flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile                   = flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")

	platformCertificateValue *common.THIMCerts = nil
	// UVM Endorsement (UVM reference info)
	// This is a base64 encoded COSE_Sign1 envelope whose issuer and feed should match Confidential ACIs signing identity
	// The payload is a json file containing two fields:
	// - x-ms-sevsnpvm-guestsvn
	//   This is a version number of the Utility VM that the container is running on.
	// - x-ms-sevsnpvm-measurement
	//   This is the SHA256 hash of the Utility VM's measurement. It should match the MEASUREMENT field in the attestation report
	uvmEndorsementValue []byte = nil
)

type server struct {
	pb.AttestationContainerServer
}

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	reportData := [attest.REPORT_DATA_SIZE]byte{}
	if len(in.GetReportData()) > attest.REPORT_DATA_SIZE {
		return nil, status.Errorf(codes.InvalidArgument, "`report_data` needs to be smaller than %d bytes. size: %d bytes", attest.REPORT_DATA_SIZE, len(in.GetReportData()))
	}
	copy(reportData[:], in.GetReportData())
	if *insecureVirtual {
		logrus.Trace("Serving virtual attestation report")
		return &pb.FetchAttestationReply{}, nil
	}

	logrus.Trace("Fetching attestation report...")
	reportFetcher := attest.NewAttestationReportFetcher()
	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch attestation report: %s", err)
	}

	logrus.Trace("Setting platform certificate...")
	var platformCertificate []byte
	if platformCertificateValue == nil {
		logrus.Trace("Deserializing attestation report...")
		var SNPReport attest.SNPAttestationReport
		if err = SNPReport.DeserializeReport(reportBytes); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to deserialize attestation report: %s", err)
		}
		var certFetcher attest.CertFetcher
		if *platformCertificateServer == "AMD" {
			logrus.Trace("Setting AMD Certificate Fetcher...")
			certFetcher = attest.DefaultAMDMilanCertFetcherNew()
		} else {
			// Use "Azure". The value of platformCertificateServer should be already checked.
			logrus.Trace("Setting Azure Certificate Fetcher...")
			certFetcher = attest.DefaultAzureCertFetcherNew()
		}
		logrus.Trace("Fetching platform certificate...")
		platformCertificate, _, err = certFetcher.GetCertChain(SNPReport.ChipID, SNPReport.ReportedTCB)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to fetch platform certificate: %s", err)
		}
	} else {
		logrus.Trace("Using platform certificate from UVM info...")
		platformCertificate = append(platformCertificate, platformCertificateValue.VcekCert...)
		platformCertificate = append(platformCertificate, platformCertificateValue.CertificateChain...)
	}

	return &pb.FetchAttestationReply{Attestation: reportBytes, PlatformCertificates: platformCertificate, UvmEndorsements: uvmEndorsementValue}, nil
}

func validateFlags() {
	if *platformCertificateServer != "" && *platformCertificateServer != "AMD" && *platformCertificateServer != "Azure" {
		logrus.Fatalf("invalid --platform-certificate-server value %s (valid values: 'AMD', 'Azure')", *platformCertificateServer)
	}
}

func main() {
	flag.Parse()

	// if logFile is not set, logrus defaults to stderr
	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()
		multi := io.MultiWriter(file, os.Stderr)
		logrus.SetOutput(multi)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	validateFlags()

	logrus.Info("Attestation container started...")

	if *insecureVirtual {
		logrus.Warn("Warning: INSECURE virtual: do not use in production!")
	} else {
		logrus.Trace("Checking if SNP device is detected...")
		if _, err := os.Stat(attest.SNP_DEVICE_PATH); err == nil {
			logrus.Tracef("%s is detected\n", attest.SNP_DEVICE_PATH)
		} else if errors.Is(err, os.ErrNotExist) {
			logrus.Fatalf("%s is not detected", attest.SNP_DEVICE_PATH)
		} else {
			logrus.Fatalf("Unknown error: %s", err)
		}

		logrus.Trace("Getting UVM Information...")
		uvmInfo, err := common.GetUvmInformation()
		if err != nil {
			logrus.Fatalf("Failed to get UVM information: %s", err)
		}

		logrus.Trace("Setting platform certificate server...")
		if *platformCertificateServer == "" {
			platformCertificateValue = &uvmInfo.InitialCerts
		} else {
			logrus.Tracef("Platform certificates will be retrieved from server %s", *platformCertificateServer)
		}

		logrus.Trace("Decoding UVM reference info...")
		uvmEndorsementValue, err = base64.StdEncoding.DecodeString(uvmInfo.EncodedUvmReferenceInfo)
		if err != nil {
			logrus.Fatalf("Failed to decode base64 string: %s", err)
		}
	}

	// Cleanup
	if _, err := os.Stat(*socketAddress); err == nil {
		if err := os.RemoveAll(*socketAddress); err != nil {
			logrus.Fatalf("Failed to clean up socket: %s", err)
		} else {
			logrus.Infof("Cleaned existing socket %s", *socketAddress)
		}
	} else {
		logrus.Debugf("Failed to stat socket %s", *socketAddress)
	}

	// Create parent directory for socketAddress
	socketDir := filepath.Dir(*socketAddress)
	// os.MkdirAll doesn't return error when the directory already exists
	if err := os.MkdirAll(socketDir, os.ModePerm); err != nil {
		logrus.Fatalf("Failed to create directory for Unix domain socket: %s", err)
	}

	lis, err := net.Listen("unix", *socketAddress)
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAttestationContainerServer(s, &server{})
	logrus.Infof("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}
