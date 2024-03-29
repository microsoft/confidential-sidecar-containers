// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build !skip_e2e && !skip_snp_required

// E2E test. Requires to run `go run .` before running it.
// It also requires to be ran inside SNP VM.
// When you run tests from the project root, you can skip it by
// `go test ./... -tags skip_e2e` or `go test ./... -tags skip_snp_required`,
// or even `go test ./... -tags skip_e2e,skip_snp_required`.

package main

import (
	"context"
	"encoding/pem"
	"flag"
	"net"
	"testing"
	"time"

	pb "github.com/Microsoft/confidential-sidecar-containers/cmd/attestation-container/protobuf"

	"google.golang.org/grpc"
)

var (
	addr = flag.String("addr", "/tmp/attestation-container.sock", "the Unix domain socket address to connect to")
)

const TIMEOUT_IN_SEC = 10

func splitPemChain(pemChain []byte) [][]byte {
	var chain [][]byte
	var certDERBlock *pem.Block
	for {
		certDERBlock, pemChain = pem.Decode(pemChain)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			chain = append(chain, certDERBlock.Bytes)
		}
	}
	return chain
}

func TestFetchReport(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	dialer := func(addr string, t time.Duration) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		t.Fatalf("did not connect. attestation-container needs to be run before run this test: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_IN_SEC*time.Second)
	defer cancel()
	// public key bytes in UTF-8 (https://go.dev/blog/strings)
	publicKey := []byte("public-key-contents")
	r, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey})
	if err != nil {
		t.Fatalf("could not get attestation. attestation-container needs to be run before run this test: %v", err)
	}
	// Verify attestation
	attestation := r.GetAttestation()
	if len(attestation) == 0 {
		t.Fatalf("attestation is empty")
	}

	// Verify platform certificates
	platformCertificates := r.GetPlatformCertificates()
	if len(platformCertificates) == 0 {
		t.Fatalf("platformCertificates is empty")
	}
	chainLen := len(splitPemChain(platformCertificates))
	if chainLen != 3 {
		// Expecting VCEK, ASK and ARK
		t.Fatalf("platformCertificates does not contain 3 certificates, found %d", chainLen)
	}

	if len(r.GetUvmEndorsements()) == 0 {
		t.Fatalf("UVM endorsement is empty")
	}
}

func TestInputError(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	dialer := func(addr string, t time.Duration) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_IN_SEC*time.Second)
	defer cancel()
	publicKey := []byte("too long (longer than 64 bytes in utf-8) ------------------------")
	if _, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey}); err == nil {
		t.Fatalf("server should return input error for too large input")
	}
}
