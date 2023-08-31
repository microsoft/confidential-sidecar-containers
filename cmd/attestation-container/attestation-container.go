// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"

	pb "github.com/Microsoft/confidential-sidecar-containers/cmd/attestation-container/protobuf"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	socketAddress             = flag.String("socket-address", "/tmp/attestation-container.sock", "The socket address of Unix domain socket (UDS)")
	platformCertificateServer = flag.String("platform-certificate-server", "", "Server to fetch platform certificate. If set, certificates contained in security context directory are ignored. Value is either 'Azure' or 'AMD'")
	insecureVirtual           = flag.Bool("insecure-virtual", false, "If set, dummy attestation is returned (INSECURE: do not use in production)")

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
		log.Println("Serving virtual attestation report")
		return &pb.FetchAttestationReply{}, nil
	}

	var reportFetcher attest.AttestationReportFetcher
	if attest.IsSNPVM5() {
		reportFetcher = attest.NewAttestationReportFetcher()
	} else if attest.IsSNPVM6() {
		reportFetcher = attest.NewAttestationReportFetcher6()
	} else {
		return nil, status.Errorf(codes.Internal, "attestation-container is not running in SNP enabled VM")
	}

	reportBytes, err := reportFetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch attestation report: %s", err)
	}

	var platformCertificate []byte
	if platformCertificateValue == nil {
		var SNPReport attest.SNPAttestationReport
		if err = SNPReport.DeserializeReport(reportBytes); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to deserialize attestation report: %s", err)
		}
		var certFetcher attest.CertFetcher
		if *platformCertificateServer == "AMD" {
			certFetcher = attest.DefaultAMDMilanCertFetcherNew()
		} else {
			// Use "Azure". The value of platformCertificateServer should be already checked.
			certFetcher = attest.DefaultAzureCertFetcherNew()
		}
		platformCertificate, _, err = certFetcher.GetCertChain(SNPReport.ChipID, SNPReport.ReportedTCB)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to fetch platform certificate: %s", err)
		}
	} else {
		platformCertificate = append(platformCertificate, platformCertificateValue.VcekCert...)
		platformCertificate = append(platformCertificate, platformCertificateValue.CertificateChain...)
	}

	return &pb.FetchAttestationReply{Attestation: reportBytes, PlatformCertificates: platformCertificate, UvmEndorsements: uvmEndorsementValue}, nil
}

func validateFlags() {
	if *platformCertificateServer != "" && *platformCertificateServer != "AMD" && *platformCertificateServer != "Azure" {
		log.Fatalf("invalid --platform-certificate-server value %s (valid values: 'AMD', 'Azure')", *platformCertificateServer)
	}
}

func main() {
	flag.Parse()
	validateFlags()

	log.Println("Attestation container started.")

	if *insecureVirtual {
		log.Printf("Warning: INSECURE virtual: do not use in production!")
	} else {
		if attest.IsSNPVM5() {
			log.Printf("%s is detected\n", attest.SNP_DEVICE_PATH_5)
		} else if attest.IsSNPVM6() {
			log.Printf("%s is detected\n", attest.SNP_DEVICE_PATH_6)
		} else {
			log.Fatalf("attestation-container is not running in SNP enabled VM")
		}

		uvmInfo, err := common.GetUvmInformation()
		if err != nil {
			log.Fatalf("Failed to get UVM information: %s", err)
		}

		if *platformCertificateServer == "" {
			platformCertificateValue = &uvmInfo.InitialCerts
		} else {
			log.Printf("Platform certificates will be retrieved from server %s", *platformCertificateServer)
		}

		uvmEndorsementValue, err = base64.StdEncoding.DecodeString(uvmInfo.EncodedUvmReferenceInfo)
		if err != nil {
			log.Fatalf("Failed to decode base64 string: %s", err)
		}
	}

	// Cleanup
	if _, err := os.Stat(*socketAddress); err == nil {
		if err := os.RemoveAll(*socketAddress); err != nil {
			log.Fatalf("Failed to clean up socket: %s", err)
		}
	}

	// Create parent directory for socketAddress
	socketDir := filepath.Dir(*socketAddress)
	// os.MkdirAll doesn't return error when the directory already exists
	if err := os.MkdirAll(socketDir, os.ModePerm); err != nil {
		log.Fatalf("Failed to create directory for Unix domain socket: %s", err)
	}

	lis, err := net.Listen("unix", *socketAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAttestationContainerServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
