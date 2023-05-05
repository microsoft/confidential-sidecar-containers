package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"

	pb "github.com/Microsoft/confidential-sidecar-containers/cmd/attestation-container/protobuf"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/uvm"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	socketAddress                  = flag.String("socket-address", "/tmp/attestation-container.sock", "The socket address of Unix domain socket (UDS)")
	securityContextDirectoryEnvVar = flag.String("security-context-directory-envvar", attest.DEFAULT_SECURITY_CONTEXT_ENVVAR, "Name of environment variable specifying name of directory containing confidential ACI security context")
	platformCertificateServer      = flag.String("platform-certificate-server", "", "Server to fetch platform certificate. If set, certificates contained in security context directory are ignored. Value is either 'Azure' or 'AMD'")
	insecureVirtual                = flag.Bool("insecure-virtual", false, "If set, dummy attestation is returned (INSECURE: do not use in production)")

	platformCertificateValue  *attest.ACICertificates = nil
	uvmEndorsementEnvVarValue []byte                  = nil
)

type server struct {
	pb.UnimplementedAttestationContainerServer
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

	reportBytes, err := attest.FetchAttestationReportByte(reportData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch attestation report: %s", err)
	}

	var platformCertificate []byte
	if platformCertificateValue == nil {
		reportedTCBBytes := reportBytes[attest.REPORTED_TCB_OFFSET : attest.REPORTED_TCB_OFFSET+attest.REPORTED_TCB_SIZE]
		chipIDBytes := reportBytes[attest.CHIP_ID_OFFSET : attest.CHIP_ID_OFFSET+attest.CHIP_ID_SIZE]
		platformCertificate, err = attest.FetchPlatformCertificate(*platformCertificateServer, reportedTCBBytes, chipIDBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to fetch platform certificate: %s", err)
		}
	} else {
		platformCertificate = append(platformCertificate, platformCertificateValue.VcekCert...)
		platformCertificate = append(platformCertificate, platformCertificateValue.CertificateChain...)
	}

	return &pb.FetchAttestationReply{Attestation: reportBytes, PlatformCertificates: platformCertificate, UvmEndorsements: uvmEndorsementEnvVarValue}, nil
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
		if _, err := os.Stat(attest.SNP_DEVICE_PATH); err == nil {
			log.Printf("%s is detected\n", attest.SNP_DEVICE_PATH)
		} else if errors.Is(err, os.ErrNotExist) {
			log.Fatalf("%s is not detected", attest.SNP_DEVICE_PATH)
		} else {
			log.Fatalf("Unknown error: %s", err)
		}

		securityContextDirectory, ok := os.LookupEnv(*securityContextDirectoryEnvVar)
		if !ok {
			log.Fatalf("Security context directory %s is not specified", *securityContextDirectoryEnvVar)
		}

		if *platformCertificateServer == "" {
			platformCertificateValue = new(attest.ACICertificates)
			var err error
			*platformCertificateValue, err = attest.ParseCertificateACIFromSecurityContextDirectory(securityContextDirectory)
			if err != nil {
				log.Fatalf(err.Error())
			}
		} else {
			log.Printf("Platform certificates will be retrieved from server %s", *platformCertificateServer)
		}

		var err error
		uvmEndorsementEnvVarValue, err = uvm.ParseUVMEndorsement(securityContextDirectory)
		if err != nil {
			log.Fatalf(err.Error())
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
