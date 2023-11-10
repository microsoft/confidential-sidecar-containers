// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/grpc/keyprovider"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	keyprovider.UnimplementedKeyProviderServiceServer
}

type AzureInformation struct {
	// Endpoint of the certificate cache service from which
	// the certificate chain endorsing hardware attestations
	// can be retrieved. This is optinal only when the container
	// will expose attest/maa and key/release APIs.
	CertFetcher attest.CertFetcher `json:"certcache,omitempty"`

	// Identifier of the managed identity to be used
	// for authenticating with AKV MHSM. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

var (
	ServerCertState       attest.CertState
	azure_info            AzureInformation
	EncodedUvmInformation common.UvmInformation
	SkrSideCarArgs        = "SkrSideCarArgs"
	CorruptedTCB          = "ffffffff"
)

const (
	AASP = "aasp"
)

type DecryptConfig struct {
	Parameters map[string][]string
}

type EncryptConfig struct {
	Parameters map[string][]string
	Dc         DecryptConfig
}

type KeyWrapParams struct {
	Ec       EncryptConfig `json:"ec,omitempty"`
	Optsdata string        `json:"optsdata,omitempty"`
}

type KeyUnwrapParams struct {
	Dc         DecryptConfig `json:"dc,omitempty"`
	Annotation string        `json:"annotation"`
}

type AnnotationPacket struct {
	Kid              string `json:"kid"`
	WrappedData      []byte `json:"wrapped_data"`
	Iv               []byte `json:"iv,omitempty"`
	WrapType         string `json:"wrap_type,omitempty"`
	KmsEndpoint      string `json:"kms_endpoint,omitempty"`
	AttesterEndpoint string `json:"attester_endpoint,omitempty"`
}

type RSAKeyInfo struct {
	PublicKeyPath    string `json:"public_key_path"`
	KmsEndpoint      string `json:"kms_endpoint"`
	AttesterEndpoint string `json:"attester_endpoint"`
}

type keyProviderInput struct {
	// Operation is either "keywrap" or "keyunwrap"
	// attestation-agent can only handle the case of "keyunwrap"
	Op string `json:"op"`
	// For attestation-agent, keywrapparams should be empty.
	KeyWrapParams   KeyWrapParams   `json:"keywrapparams,omitempty"`
	KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams,omitempty"`
}

type KeyUnwrapResults struct {
	OptsData []byte `json:"optsdata"`
}

type KeyWrapResults struct {
	Annotation []byte `json:"annotation"`
}

type KeyProviderProtocolOutput struct {
	// KeyWrapResult encodes the results to key wrap if operation is to wrap
	KeyWrapResults KeyWrapResults `json:"keywrapresults,omitempty"`
	// KeyUnwrapResult encodes the result to key unwrap if operation is to unwrap
	KeyUnwrapResults KeyUnwrapResults `json:"keyunwrapresults,omitempty"`
}

func (s *Server) SayHello(ctx context.Context, in *keyprovider.HelloRequest) (*keyprovider.HelloReply, error) {
	log.Printf("Received: %v", in.GetName())
	return &keyprovider.HelloReply{Message: "Hello " + in.GetName()}, nil
}

func directWrap(optsdata []byte, key_path string) ([]byte, error) {
	_, kid := path.Split(key_path)
	var annotation AnnotationPacket
	annotation.Kid = kid
	annotation.Iv = []byte("")
	annotation.WrapType = "rsa_3072"

	var keyInfo RSAKeyInfo
	path := key_path + "-info.json"
	keyInfoBytes, e := os.ReadFile(path)
	if e != nil {
		return nil, fmt.Errorf("failed to read key info file %v", path)
	}

	err := json.Unmarshal(keyInfoBytes, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA key info file %v", path)
	}
	log.Printf("%v", keyInfo)

	annotation.AttesterEndpoint = keyInfo.AttesterEndpoint
	annotation.KmsEndpoint = keyInfo.KmsEndpoint

	pubpem, err := os.ReadFile(keyInfo.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file %v", keyInfo.PublicKeyPath)
	}
	block, _ := pem.Decode([]byte(pubpem))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in %v, error: %v", path, err)
	}

	var ciphertext []byte
	if pubkey, ok := key.(*rsa.PublicKey); ok {
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, optsdata, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt with the public key %v", err)
		}
	} else {
		return nil, fmt.Errorf("invalid public RSA key in %v", path)
	}

	annotation.WrappedData = ciphertext
	annotationBytes, _ := json.Marshal(annotation)

	return annotationBytes, nil
}

func (s *Server) WrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var ec = input.KeyWrapParams.Ec
	if len(ec.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in the encryption config parameters: %v", ec)
	}
	aaKid, _ := base64.StdEncoding.DecodeString(ec.Parameters["attestation-agent"][0])
	tokens := strings.Split(string(aaKid), ":")

	if len(tokens) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "Key id is not provided in the request")
	}

	aa := tokens[0]
	kid := tokens[1]
	if !strings.EqualFold(aa, AASP) {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", aa)
	}
	log.Printf("Attestation agent: %v, kid: %v", aa, kid)

	optsdata, err := base64.StdEncoding.DecodeString(input.KeyWrapParams.Optsdata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Optsdata is not base64 encoding: %v", err)
	}

	annotationBytes, e := directWrap(optsdata, kid)
	if e != nil {
		return nil, status.Errorf(codes.Internal, "%v", e)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyWrapResults: KeyWrapResults{Annotation: annotationBytes},
	})

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil
}

func (s *Server) UnWrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var dc = input.KeyUnwrapParams.Dc
	if len(dc.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in decryption config parameters: %v", str)
	}
	aa, _ := base64.StdEncoding.DecodeString(dc.Parameters["attestation-agent"][0])
	log.Printf("Attestation agent name: %v", string(aa))

	if !strings.EqualFold(string(aa), AASP) {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", string(aa))
	}

	var annotationBytes []byte
	annotationBytes, err = base64.StdEncoding.DecodeString(input.KeyUnwrapParams.Annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Annotation is not a base64 encoding: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Decoded annotation: %v", string(annotationBytes))

	var annotation AnnotationPacket
	err = json.Unmarshal(annotationBytes, &annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed annotation packet: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Annotation packet: %v", annotation)

	mhsm := common.AKV{
		Endpoint:   annotation.KmsEndpoint,
		APIVersion: "api-version=7.4",
	}

	maa := common.MAA{
		Endpoint:   annotation.AttesterEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := common.KeyBlob{
		KID:       annotation.Kid,
		Authority: maa,
		AKV:       mhsm,
	}

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	keyBytes, err := skr.SecureKeyRelease(azure_info.Identity, ServerCertState, skrKeyBlob, EncodedUvmInformation)
	if err != nil {
		return nil, errors.Wrapf(err, "SKR failed")
	}
	logrus.Debugf("Key released of type %s", keyBytes.KeyType())

	rsaPrivatekey, err := common.RSAPrivateKeyFromJWK(&keyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "Released key is not a RSA private key")
	}

	var plaintext []byte
	plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivatekey, annotation.WrappedData, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "Unwrapping failed")
	}

	var protocolBytes []byte
	protocolBytes, err = json.Marshal(KeyProviderProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "Unwrapping failed")
	}

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil
}

func (s *Server) GetReport(c context.Context, in *keyprovider.KeyProviderGetReportInput) (*keyprovider.KeyProviderGetReportOutput, error) {
	reportDataStr := in.GetReportDataHexString()
	log.Printf("Received report data: %v", reportDataStr)

	// Fetch the attestation report

	var reportFetcher attest.AttestationReportFetcher
	if !attest.IsSNPVM() {
		return nil, status.Error(codes.FailedPrecondition, "SEV guest driver is missing.")
	}
	reportFetcher, err := attest.NewAttestationReportFetcher()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve attestation report, %s", err)
	}

	reportData := attest.GenerateMAAReportData([]byte(reportDataStr))
	SNPReportHex, err := reportFetcher.FetchAttestationReportHex(reportData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve attestation report, %s", err)
	}

	return &keyprovider.KeyProviderGetReportOutput{
		ReportHexString: SNPReportHex,
	}, nil
}

func DirectWrap(optsdata []byte, key_path string) ([]byte, error) {
	_, kid := path.Split(key_path)
	var annotation AnnotationPacket
	annotation.Kid = kid
	annotation.Iv = []byte("")
	annotation.WrapType = "rsa_3072"

	var keyInfo RSAKeyInfo
	path := key_path + "-info.json"
	keyInfoBytes, e := os.ReadFile(path)
	if e != nil {
		return nil, fmt.Errorf("failed to read key info file %v", path)
	}

	err := json.Unmarshal(keyInfoBytes, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA key info file %v", path)
	}
	log.Printf("%v", keyInfo)

	annotation.AttesterEndpoint = keyInfo.AttesterEndpoint
	annotation.KmsEndpoint = keyInfo.KmsEndpoint

	pubpem, err := os.ReadFile(keyInfo.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file %v", keyInfo.PublicKeyPath)
	}
	block, _ := pem.Decode([]byte(pubpem))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in %v, error: %v", path, err)
	}

	var ciphertext []byte
	if pubkey, ok := key.(*rsa.PublicKey); ok {
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, optsdata, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt with the public key %v", err)
		}
	} else {
		return nil, fmt.Errorf("invalid public RSA key in %v", path)
	}

	annotation.WrappedData = ciphertext
	annotationBytes, _ := json.Marshal(annotation)

	return annotationBytes, nil
}
