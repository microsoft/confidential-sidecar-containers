// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package skr

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

func Test_Keywrap(t *testing.T) {
	type aesunwrappaddingTestcase struct {
		name string

		kek     []byte
		wrapKey []byte

		expectedError   error
		expectErr       bool
		expectedContent []byte
		expectMatch     bool
	}

	// Test cases taken from RFC-5649
	kek, err := hex.DecodeString("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	encKey1, err := hex.DecodeString("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	key1, err := hex.DecodeString("c37b7e6492584340bed12207808941155068f738")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	encKey2, err := hex.DecodeString("afbeb0f07dfbf5419200f2ccb50bb24f")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	key2, err := hex.DecodeString("466f7250617369")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	boguskek, err := hex.DecodeString("5840df6e29b02af1ab493b70ddf16ea1ae8338f4dcc176a8")
	if err != nil {
		t.Fatal("unable to decode string")
	}

	aesunwrappaddingTestcases := []*aesunwrappaddingTestcase{
		// test passes if the expected result matches the result in the first test case from the RFC
		{
			name: "AESUnwrapPadding_Success_20Bytes",

			kek:     kek,
			wrapKey: encKey1,

			expectedError:   nil,
			expectErr:       false,
			expectedContent: key1,
			expectMatch:     true,
		},
		// test passes if the expected result matches the result in the second test case from the RFC
		{
			name: "AESUnwrapPadding_Success_7Bytes",

			kek:     kek,
			wrapKey: encKey2,

			expectedError:   nil,
			expectErr:       false,
			expectedContent: key2,
			expectMatch:     true,
		},
		// test passes as we unwrap the material with the wrong kek resulting in integrity check failure
		{
			name: "AESUnwrapPadding_WrongKek",

			kek:     boguskek,
			wrapKey: encKey1,

			expectedError: errors.New("integrity check failed - unexpected AIV"),
			expectErr:     true,
		},
	}

	for _, tc := range aesunwrappaddingTestcases {
		t.Run(tc.name, func(t *testing.T) {
			if cipher, err := aes.NewCipher(tc.kek); err != nil {
				t.Fatal("new aes cipher generation failed")
			} else {
				key, err := common.AesUnwrapPadding(cipher, tc.wrapKey)

				switch {
				case tc.expectErr && err == nil:
					{
						t.Fatal("expected err got nil")
					}
				case tc.expectErr && !strings.Contains(err.Error(), tc.expectedError.Error()):
					{
						t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
					}
				case !tc.expectErr:
					{
						if err != nil {
							t.Fatalf("did not expect err got %q", err.Error())
						}

						if tc.expectMatch && !bytes.Equal(tc.expectedContent, key) {
							t.Fatalf("expected %v == %v", tc.expectedContent, key)
						} else if !tc.expectMatch && bytes.Equal(tc.expectedContent, key) {
							t.Fatalf("expected %v != %v", tc.expectedContent, key)
						}
					}
				}
			}
		})
	}
}

// Generates cert chain consists of root cert, intermediate cert, and leaf cert
func generateTestCerts(dnsName string) ([]string, error) {
	const keyLength = 2048
	dateNow := time.Now()
	dateTenYearsLater := dateNow.AddDate(10, 0, 0)

	// Root certificate
	rootPrivateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		panic(err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore: dateNow,
		NotAfter:  dateTenYearsLater,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDerBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootPrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		panic(err)
	}

	intermediatePrivateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		panic(err)
	}

	// Intermediate certificate
	intermediateTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Intermediate CA",
		},
		NotBefore: dateNow,
		NotAfter:  dateTenYearsLater,

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intermediateDerBytes, err := x509.CreateCertificate(rand.Reader, &intermediateTemplate, &rootTemplate, &intermediatePrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		panic(err)
	}

	// Leaf certificate
	leafPrivateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		panic(err)
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:             dateNow,
		NotAfter:              dateTenYearsLater,
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            0,
		DNSNames:              []string{dnsName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDerBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &intermediateTemplate, &leafPrivateKey.PublicKey, intermediatePrivateKey)
	if err != nil {
		panic(err)
	}

	// return base64-encoded certificates
	certs := []string{
		base64.StdEncoding.EncodeToString(leafDerBytes),
		base64.StdEncoding.EncodeToString(intermediateDerBytes),
		base64.StdEncoding.EncodeToString(rootDerBytes),
	}
	return certs, nil

}

func Test_AKV(t *testing.T) {
	// JWS token validation
	type jwstokenValidationTestcase struct {
		name string

		token []string

		expectedError error
		expectErr     bool
	}

	jwstokenValidationTestcases := []*jwstokenValidationTestcase{
		// test passes if there is no error returned
		{
			name: "JWSTokenValidation_Success",

			token: []string{"a.b.c"},

			expectedError: nil,
			expectErr:     false,
		},
		// test passes only if all strings are found to be invalid due to wrong length
		{
			name: "JWSTokenValidation_Fail",

			token: []string{"a.b.c.d", "a.b", "a"},

			expectedError: errors.Errorf("jws token validation failed"),
			expectErr:     true,
		},
	}

	for _, tc := range jwstokenValidationTestcases {
		t.Run(tc.name, func(t *testing.T) {
			for _, token := range tc.token {
				err := common.VerifyJWSToken(token)

				switch {
				case tc.expectErr && err == nil:
					{
						t.Fatal("expected err got nil")
					}
				case tc.expectErr && err.Error() != tc.expectedError.Error():
					{
						t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
					}
				case !tc.expectErr && err != nil:
					{
						t.Fatalf("did not expect err got %q", err.Error())
					}
				}
			}
		})
	}

	// x509 certificate parsing
	type certParsingTestcase struct {
		name string

		certstring string

		expectedError error
		expectErr     bool
	}

	certParsingTestcases := []*certParsingTestcase{
		// passes if the certificate is parsed returning nil error
		{
			name: "X509ParseCertificate_Success",

			certstring: "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",

			expectedError: nil,
			expectErr:     false,
		},
		// passes if the certificate decoding fails
		{
			name: "X509ParseCertificate_NonValidBase64String",

			certstring: "MI",

			expectedError: errors.New("decoding x509 certificate from string failed: MI"),
			expectErr:     true,
		},
		// passes if the certificate is parsed and found to be a non valid x509 cert
		{
			name: "X509ParseCertificate_NonValidX509",

			certstring: "MIII",

			expectedError: errors.New("parsing certificate failed"),
			expectErr:     true,
		},
	}

	for _, tc := range certParsingTestcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := common.ParseX509Certificate(tc.certstring)

			switch {
			case tc.expectErr && err == nil:
				{
					t.Fatal("expected err got nil")
				}
			case tc.expectErr && !strings.Contains(err.Error(), tc.expectedError.Error()):
				{
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			case !tc.expectErr && err != nil:
				{
					t.Fatalf("did not expect err got %q", err.Error())
				}
			}
		})
	}

	// Cert chain verification
	type certchainVerificationTestcase struct {
		name string

		x5c []string

		root    string
		dnsName string

		expectedError error
		expectErr     bool
	}
	certDNSName := "test-confidential-sidecar"
	generatedCerts, err := generateTestCerts(certDNSName)
	if err != nil {
		t.Fatalf("failed to generate test certs: %v", err)
	}

	certchainVerificationTestcases := []*certchainVerificationTestcase{
		// this test passes because the cert chain is complete rooted to the trusted root certificate
		{
			name:          "X509CertChainVerification_Success",
			x5c:           generatedCerts,
			root:          generatedCerts[len(generatedCerts)-1],
			dnsName:       certDNSName,
			expectedError: nil,
			expectErr:     false,
		},
		// this test passes because it is found that the leaf certificate is issued by a non-expecting server
		{
			name:          "X509CertChainVerification_NonMatchingDNSName",
			x5c:           generatedCerts,
			root:          generatedCerts[len(generatedCerts)-1],
			dnsName:       "a.com",
			expectedError: errors.New("certificate is valid for"),
			expectErr:     true,
		},
		// this test passes because it is found that although the cert chain is complete it is not rooted to the trusted root
		{
			name:          "X509CertChainVerification_NoTrustedRoot",
			x5c:           generatedCerts,
			root:          "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoXDTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9yZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVyVHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKrmD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjrIZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeKmpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSuXmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZydc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/yejl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT929hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3WgxjkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhzksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLSR9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp",
			dnsName:       certDNSName,
			expectedError: errors.New("certificate signed by unknown authority"),
			expectErr:     true,
		},
		// this test passes because it is found that the cert chain is not complete as there is an intermediate cert missing
		{
			name: "X509CertChainVerification_NoIntermediate",
			x5c: []string{
				generatedCerts[0], generatedCerts[len(generatedCerts)-1],
			},
			root:          generatedCerts[len(generatedCerts)-1],
			dnsName:       certDNSName,
			expectedError: errors.New("certificate signed by unknown authority"),
			expectErr:     true,
		},
		// this test passes because it is found that the cert chain has expired
		{
			name: "X509CertChainVerification_Expired",
			x5c: []string{
				"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",
			},

			root: "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTflMrY=",

			dnsName:       "svolos-myhsm-01.managedhsm.azure.net",
			expectedError: errors.New("x509: certificate has expired or is not yet valid"),
			expectErr:     true,
		},
	}

	for _, tc := range certchainVerificationTestcases {
		t.Run(tc.name, func(t *testing.T) {

			roots := x509.NewCertPool()

			if root, err := common.ParseX509Certificate(tc.root); err != nil {
				t.Fatalf("not valid root certificate: %s", err)
			} else {
				roots.AddCert(root)
			}

			err := common.VerifyX509CertChain(tc.dnsName, tc.x5c, roots)

			switch {
			case tc.expectErr && err == nil:
				{
					t.Fatal("expected err got nil")
				}
			case tc.expectErr && !strings.Contains(err.Error(), tc.expectedError.Error()):
				{
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			case !tc.expectErr && err != nil:
				{
					t.Fatalf("did not expect err got %q", err.Error())
				}
			}
		})
	}

	// JWS token signature validation
	type jwstokenSignatureValidationTestcase struct {
		name string

		signedPayload []byte
		pubkey        interface{}

		expectedError   error
		expectErr       bool
		expectedContent string
		expectMatch     bool
	}

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("failed to create private key")
	}
	const payload = "Lorem ipsum"
	const bogusPayload = "Lorem ipsum Bogus"
	signed, err := jws.Sign([]byte(payload), jwa.RS256, privkey)
	if err != nil {
		t.Fatal("failed to sign payload")
	}

	// [SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine", Justification="Test Data")]
	boguskey, err := common.PrivateKeyFromPEM("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAv965SRmyp8zbG5eNFuDCmmiSeaHpujG2bC/keLSuzvDMLO1W\nyrUJveaa5bzMoO0pA46pXkmbqHisozVzpiNDLCo6d3z4TrGMeFPf2APIMu+RSrzN\n56qvHVyIr5caWfHWk+FMRDwAefyNYRHkdYYkgmFK44hhUdtlCAKEv5UQpFZjvh4i\nI9jVBdGYMyBaKQLhjI5WIh+QG6Za5sSuOCFMnmuyuvN5DflpLFz595Ss+EoBIY+N\nil6lCtvcGgR+IbjUYHAOs5ajamTzgeO8kx3VCE9HcyKmyUZsiyiF6IDRp2Bpy3NH\nTjIz7tmkpTHx7tHnRtlfE2FUv0B6i/QYl/ZA5QIDAQABAoIBAG9Ig9jFIdy3MWII\nfVmGlPgvrL0FTuWiTbbj9DSaP0VhXlq0cYFyjSrqZG7ZGSpBQ2d/x/Ya5UBKdX7X\n0rLKgvxLpcuF3RLvYZSsuQi18NiyIGfjp901Hwn9kH2fOzZt0NHGe5Cb6H7YHzvs\nv7/2RJimS2Q6xo9Om4OQymO/1n4pZ+ZMiTy56AvIYZ/ToD8lorlzkGFNQsljmTSC\nIHEqRuyttI0Tf64jNaD8K74EThlZG8AE/yNG2FiRtN37+gAgMhxNWoF64s+9D/G0\n1xL96WNP5GmxXidK4BAUwWZmLJTtgUDcGjJbmfSuEMFjpRA9wfcL717jDzB0AImO\nOnZSgWECgYEA2swHf+pU8D1vshCBCTx/wGeIMRJE1Nw3YBhvPrUCExMo8M2UAkzs\nlKq61xSnh0X7f/Ma28vj9/gT+AHOnoCSdFSFO3dxX8B3y+B3jVvbxx7P+iZrM8J+\nVgrqPaXrIpBNPCooieD6O9EGvyC0+somgvtkA3ne2jdxX1rbPaQZr5kCgYEA4H6Y\ndWb2F5Dglhby9oXfjaLslIumoTTRFTgygIXHBG0auwMQzwfhuLyzH55mBICn16Ez\nLRyqssna5NgfTF0XrZT/BIPo8dSj0hlWvDtvCnZbDMTLYrk+GdypJD2oWmsbB6gB\nFjdjU4pv8c/4WjGuuWJ8Vs47+HTBNJlJlr6fWy0CgYBapPJqdRtxWBKBM8Mxn2XR\nwVKz+byYbw9l+VmFIhpU6rgoYxLxjQrqYHz9hCoPqdeS35V9/89XOOiU87K1CdEi\n7q0vwMEwiR1YUotU/fxkVwiUuvvouqf6X5VBqw5qCFxnE5Qt4w3oYCWqYxN3Xu5r\nj1iU9BV2VEfc2FhCBk056QKBgQDChm/tKy6K9QrmgzQ80XwI6ug9P1U/0thpnqyE\nGWd+OlwzOFDUVGwO+9PqzgJwXFsTyabirDhte+Ok8HEOZowh6T2g1/x9sFfTsgkq\nSgXJ9wymX9As138sQbx+nr7GupBNbhKjAZObzBV8X01AOlTAZsp/HW1xuRnBTiIp\n8Tt8cQKBgQDUv6Jpe1/kO0YJ6KlqVcMIZa+aQFamoMavlCNxxBvjoPnVdWB9PtWi\narzVMyAVvTjnT1QvGPJj1dffE+GSrAf3mssdp/tGfMGcgSB0DRcE1jz/JlzEc81F\no9Ki1lCw8ljoaNfJ8K+7wdiQ1V/H+rgL691P/2ZGc4vdOXJvy/hGZA==\n-----END RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatal("Could not create private key from PEM")
	}

	jwstokenSignatureValidationTestcases := []*jwstokenSignatureValidationTestcase{
		// this test passes because the signature is validated returning a nil error
		{
			name: "JWSTokenSignatureValidation_Success",

			signedPayload: signed,
			pubkey:        privkey.PublicKey,

			expectedError:   nil,
			expectErr:       false,
			expectedContent: payload,
			expectMatch:     true,
		},
		// this test passes because the content does not match the signed payload
		{
			name: "JWSTokenSignatureValidation_DifferentPayload",

			signedPayload: signed,
			pubkey:        privkey.PublicKey,

			expectedError:   nil,
			expectErr:       false,
			expectedContent: bogusPayload,
			expectMatch:     false,
		},
		// this test passes because the signature is corrupted returning the expected error
		{
			name: "JWSTokenSignatureValidation_CorruptedSignature",

			signedPayload: make([]byte, 4),
			pubkey:        privkey.PublicKey,

			expectedError: errors.Errorf("jws token verification failed: failed extract from compact serialization format: invalid number of segments"),
			expectErr:     true,
		},
		// this test passes because the payload has been signed with a different key returning the expected error
		{
			name: "JWSTokenSignatureValidation_DifferentSigningKey",

			signedPayload: signed,
			pubkey:        boguskey.PublicKey,

			expectedError: errors.Errorf("jws token verification failed: failed to verify message: crypto/rsa: verification error"),
			expectErr:     true,
		},
	}

	for _, tc := range jwstokenSignatureValidationTestcases {
		t.Run(tc.name, func(t *testing.T) {
			payloadBytes, err := common.ValidateJWSToken(string(tc.signedPayload), tc.pubkey, jwa.RS256)

			switch {
			case tc.expectErr && err == nil:
				{
					t.Fatal("expected err got nil")
				}
			case tc.expectErr && err.Error() != tc.expectedError.Error():
				{
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			case !tc.expectErr:
				{
					if err != nil {
						t.Fatalf("did not expect err got %q", err.Error())
					}

					if tc.expectMatch && !bytes.Equal([]byte(tc.expectedContent), payloadBytes) {
						t.Fatalf("expected %v == %v", tc.expectedContent, string(payloadBytes))
					} else if !tc.expectMatch && bytes.Equal([]byte(tc.expectedContent), payloadBytes) {
						t.Fatalf("expected %v != %v", tc.expectedContent, string(payloadBytes))
					}
				}
			}
		})
	}

	// RSAKeyUnwrap
	type RSAKeyUnwrapTestcase struct {
		name string

		ciphertextBase64 string
		enc              string
		privkey          *rsa.PrivateKey

		expectedError   error
		expectErr       bool
		expectedContent []byte
		expectMatch     bool
	}

	// [SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine", Justification="Test Data")]
	privkey, err = common.PrivateKeyFromPEM("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAv965SRmyp8zbG5eNFuDCmmiSeaHpujG2bC/keLSuzvDMLO1W\nyrUJveaa5bzMoO0pA46pXkmbqHisozVzpiNDLCo6d3z4TrGMeFPf2APIMu+RSrzN\n56qvHVyIr5caWfHWk+FMRDwAefyNYRHkdYYkgmFK44hhUdtlCAKEv5UQpFZjvh4i\nI9jVBdGYMyBaKQLhjI5WIh+QG6Za5sSuOCFMnmuyuvN5DflpLFz595Ss+EoBIY+N\nil6lCtvcGgR+IbjUYHAOs5ajamTzgeO8kx3VCE9HcyKmyUZsiyiF6IDRp2Bpy3NH\nTjIz7tmkpTHx7tHnRtlfE2FUv0B6i/QYl/ZA5QIDAQABAoIBAG9Ig9jFIdy3MWII\nfVmGlPgvrL0FTuWiTbbj9DSaP0VhXlq0cYFyjSrqZG7ZGSpBQ2d/x/Ya5UBKdX7X\n0rLKgvxLpcuF3RLvYZSsuQi18NiyIGfjp901Hwn9kH2fOzZt0NHGe5Cb6H7YHzvs\nv7/2RJimS2Q6xo9Om4OQymO/1n4pZ+ZMiTy56AvIYZ/ToD8lorlzkGFNQsljmTSC\nIHEqRuyttI0Tf64jNaD8K74EThlZG8AE/yNG2FiRtN37+gAgMhxNWoF64s+9D/G0\n1xL96WNP5GmxXidK4BAUwWZmLJTtgUDcGjJbmfSuEMFjpRA9wfcL717jDzB0AImO\nOnZSgWECgYEA2swHf+pU8D1vshCBCTx/wGeIMRJE1Nw3YBhvPrUCExMo8M2UAkzs\nlKq61xSnh0X7f/Ma28vj9/gT+AHOnoCSdFSFO3dxX8B3y+B3jVvbxx7P+iZrM8J+\nVgrqPaXrIpBNPCooieD6O9EGvyC0+somgvtkA3ne2jdxX1rbPaQZr5kCgYEA4H6Y\ndWb2F5Dglhby9oXfjaLslIumoTTRFTgygIXHBG0auwMQzwfhuLyzH55mBICn16Ez\nLRyqssna5NgfTF0XrZT/BIPo8dSj0hlWvDtvCnZbDMTLYrk+GdypJD2oWmsbB6gB\nFjdjU4pv8c/4WjGuuWJ8Vs47+HTBNJlJlr6fWy0CgYBapPJqdRtxWBKBM8Mxn2XR\nwVKz+byYbw9l+VmFIhpU6rgoYxLxjQrqYHz9hCoPqdeS35V9/89XOOiU87K1CdEi\n7q0vwMEwiR1YUotU/fxkVwiUuvvouqf6X5VBqw5qCFxnE5Qt4w3oYCWqYxN3Xu5r\nj1iU9BV2VEfc2FhCBk056QKBgQDChm/tKy6K9QrmgzQ80XwI6ug9P1U/0thpnqyE\nGWd+OlwzOFDUVGwO+9PqzgJwXFsTyabirDhte+Ok8HEOZowh6T2g1/x9sFfTsgkq\nSgXJ9wymX9As138sQbx+nr7GupBNbhKjAZObzBV8X01AOlTAZsp/HW1xuRnBTiIp\n8Tt8cQKBgQDUv6Jpe1/kO0YJ6KlqVcMIZa+aQFamoMavlCNxxBvjoPnVdWB9PtWi\narzVMyAVvTjnT1QvGPJj1dffE+GSrAf3mssdp/tGfMGcgSB0DRcE1jz/JlzEc81F\no9Ki1lCw8ljoaNfJ8K+7wdiQ1V/H+rgL691P/2ZGc4vdOXJvy/hGZA==\n-----END RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatal("Could not create private key from PEM")
	}

	boguskey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("failed to create private key")
	}

	RSAKeyUnwrapTestcases := []*RSAKeyUnwrapTestcase{
		// this test passes because the unwrapped key matches the expected one
		{
			name: "RSAKeyUnwrap_Success",

			ciphertextBase64: "deOO7jP6FnTc12fnCBKlpKS-ElBv-YdNimSbEVyTQaOlmc8caf8l2xa3tz6pSzjYoO7AMB-vFcftTjQyvw5ju_0uLeqRnTUQuzRkgEjoEumQAOeV3zS_5mDG6cupZWYlyihTLFSt5_1VR0t9T_FCBj0HxeHWsYJxJomlOMlyBv23f_6Fq15dxryb3CORXiUH9K0fOINmsL3DNzMKx4srAf9OssuV1VqrSKSoHLcyvG1SIHHfAXg3wEU5NfoxFiPc_a4Pv_bmvFLJ_fs1ETE3GmkuxkX-r17AtGSijJnl6H3YS-WGkDhnfTJDo6NEPGKkhabDwAxoTblA2pa71N-AW-CCBgbPy-9bFYpQyqEAIRbLeQLxLmVWm6ZVNW3iRRe9i1cUFnSEkAg",
			enc:              "CKM_RSA_AES_KEY_WRAP",
			privkey:          privkey,

			expectedError:   nil,
			expectErr:       false,
			expectedContent: []byte{216, 94, 204, 152, 58, 92, 254, 58, 95, 227, 119, 247, 157, 20, 2, 110, 115, 202, 123, 181, 74, 232, 239, 192, 216, 18, 138, 75, 136, 168, 86, 118},
			expectMatch:     true,
		},
		// this test passes because the decryption fails as the wrong enc algorithm is requested
		{
			name: "RSAKeyUnwrap_DifferentEnc",

			ciphertextBase64: "deOO7jP6FnTc12fnCBKlpKS-ElBv-YdNimSbEVyTQaOlmc8caf8l2xa3tz6pSzjYoO7AMB-vFcftTjQyvw5ju_0uLeqRnTUQuzRkgEjoEumQAOeV3zS_5mDG6cupZWYlyihTLFSt5_1VR0t9T_FCBj0HxeHWsYJxJomlOMlyBv23f_6Fq15dxryb3CORXiUH9K0fOINmsL3DNzMKx4srAf9OssuV1VqrSKSoHLcyvG1SIHHfAXg3wEU5NfoxFiPc_a4Pv_bmvFLJ_fs1ETE3GmkuxkX-r17AtGSijJnl6H3YS-WGkDhnfTJDo6NEPGKkhabDwAxoTblA2pa71N-AW-CCBgbPy-9bFYpQyqEAIRbLeQLxLmVWm6ZVNW3iRRe9i1cUFnSEkAg",
			enc:              "RSA_AES_KEY_WRAP_256",
			privkey:          privkey,

			expectedError: errors.New("OAEP decryption failed: crypto/rsa: decryption error"),
			expectErr:     true,
		},
		// this test passes because the decryption fails as the wrong key is used
		{
			name: "RSAKeyUnwrap_DifferentKey",

			ciphertextBase64: "deOO7jP6FnTc12fnCBKlpKS-ElBv-YdNimSbEVyTQaOlmc8caf8l2xa3tz6pSzjYoO7AMB-vFcftTjQyvw5ju_0uLeqRnTUQuzRkgEjoEumQAOeV3zS_5mDG6cupZWYlyihTLFSt5_1VR0t9T_FCBj0HxeHWsYJxJomlOMlyBv23f_6Fq15dxryb3CORXiUH9K0fOINmsL3DNzMKx4srAf9OssuV1VqrSKSoHLcyvG1SIHHfAXg3wEU5NfoxFiPc_a4Pv_bmvFLJ_fs1ETE3GmkuxkX-r17AtGSijJnl6H3YS-WGkDhnfTJDo6NEPGKkhabDwAxoTblA2pa71N-AW-CCBgbPy-9bFYpQyqEAIRbLeQLxLmVWm6ZVNW3iRRe9i1cUFnSEkAg",
			enc:              "CKM_RSA_AES_KEY_WRAP",
			privkey:          boguskey,

			expectedError: errors.New("OAEP decryption failed: crypto/rsa: decryption error"),
			expectErr:     true,
		},
		// this test passes because the enc alg is not a valid one
		{
			name: "RSAKeyUnwrap_InvalidEnc",

			ciphertextBase64: "deOO7jP6FnTc12fnCBKlpKS-ElBv-YdNimSbEVyTQaOlmc8caf8l2xa3tz6pSzjYoO7AMB-vFcftTjQyvw5ju_0uLeqRnTUQuzRkgEjoEumQAOeV3zS_5mDG6cupZWYlyihTLFSt5_1VR0t9T_FCBj0HxeHWsYJxJomlOMlyBv23f_6Fq15dxryb3CORXiUH9K0fOINmsL3DNzMKx4srAf9OssuV1VqrSKSoHLcyvG1SIHHfAXg3wEU5NfoxFiPc_a4Pv_bmvFLJ_fs1ETE3GmkuxkX-r17AtGSijJnl6H3YS-WGkDhnfTJDo6NEPGKkhabDwAxoTblA2pa71N-AW-CCBgbPy-9bFYpQyqEAIRbLeQLxLmVWm6ZVNW3iRRe9i1cUFnSEkAg",
			enc:              "MY_OWN_WRAP",
			privkey:          privkey,

			expectedError: errors.New("Unsupported hash for the wrapping protocol"),
			expectErr:     true,
		},
	}

	for _, tc := range RSAKeyUnwrapTestcases {
		t.Run(tc.name, func(t *testing.T) {
			// decode Ciphertext no-padding base64 url representation and wnwrap the key
			if ciphertext, err := base64.RawURLEncoding.DecodeString(tc.ciphertextBase64); err == nil {
				keyBytes, err := common.RsaAESKeyUnwrap(tc.enc, ciphertext, tc.privkey)

				switch {

				case tc.expectErr && err == nil:
					{
						t.Fatal("expected err got nil")
					}
				case tc.expectErr && err.Error() != tc.expectedError.Error():
					{
						t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
					}
				case !tc.expectErr:
					{
						if err != nil {
							t.Fatalf("did not expect err got %q", err.Error())
						}

						if tc.expectMatch && !bytes.Equal(tc.expectedContent, keyBytes) {
							t.Fatalf("expected %v == %v", tc.expectedContent, keyBytes)
						} else if !tc.expectMatch && bytes.Equal(tc.expectedContent, keyBytes) {
							t.Fatalf("expected %v != %v", tc.expectedContent, keyBytes)
						}
					}
				}
			} else {
				t.Fatal("decoding keyHSM's ciphertext failed")
			}
		})
	}
}

func Test_SKR(t *testing.T) {
	// [SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine", Justification="Test Data")]
	TestKeyBlobBytes, err := common.GenerateJWKSetFromPEM("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAv965SRmyp8zbG5eNFuDCmmiSeaHpujG2bC/keLSuzvDMLO1W\nyrUJveaa5bzMoO0pA46pXkmbqHisozVzpiNDLCo6d3z4TrGMeFPf2APIMu+RSrzN\n56qvHVyIr5caWfHWk+FMRDwAefyNYRHkdYYkgmFK44hhUdtlCAKEv5UQpFZjvh4i\nI9jVBdGYMyBaKQLhjI5WIh+QG6Za5sSuOCFMnmuyuvN5DflpLFz595Ss+EoBIY+N\nil6lCtvcGgR+IbjUYHAOs5ajamTzgeO8kx3VCE9HcyKmyUZsiyiF6IDRp2Bpy3NH\nTjIz7tmkpTHx7tHnRtlfE2FUv0B6i/QYl/ZA5QIDAQABAoIBAG9Ig9jFIdy3MWII\nfVmGlPgvrL0FTuWiTbbj9DSaP0VhXlq0cYFyjSrqZG7ZGSpBQ2d/x/Ya5UBKdX7X\n0rLKgvxLpcuF3RLvYZSsuQi18NiyIGfjp901Hwn9kH2fOzZt0NHGe5Cb6H7YHzvs\nv7/2RJimS2Q6xo9Om4OQymO/1n4pZ+ZMiTy56AvIYZ/ToD8lorlzkGFNQsljmTSC\nIHEqRuyttI0Tf64jNaD8K74EThlZG8AE/yNG2FiRtN37+gAgMhxNWoF64s+9D/G0\n1xL96WNP5GmxXidK4BAUwWZmLJTtgUDcGjJbmfSuEMFjpRA9wfcL717jDzB0AImO\nOnZSgWECgYEA2swHf+pU8D1vshCBCTx/wGeIMRJE1Nw3YBhvPrUCExMo8M2UAkzs\nlKq61xSnh0X7f/Ma28vj9/gT+AHOnoCSdFSFO3dxX8B3y+B3jVvbxx7P+iZrM8J+\nVgrqPaXrIpBNPCooieD6O9EGvyC0+somgvtkA3ne2jdxX1rbPaQZr5kCgYEA4H6Y\ndWb2F5Dglhby9oXfjaLslIumoTTRFTgygIXHBG0auwMQzwfhuLyzH55mBICn16Ez\nLRyqssna5NgfTF0XrZT/BIPo8dSj0hlWvDtvCnZbDMTLYrk+GdypJD2oWmsbB6gB\nFjdjU4pv8c/4WjGuuWJ8Vs47+HTBNJlJlr6fWy0CgYBapPJqdRtxWBKBM8Mxn2XR\nwVKz+byYbw9l+VmFIhpU6rgoYxLxjQrqYHz9hCoPqdeS35V9/89XOOiU87K1CdEi\n7q0vwMEwiR1YUotU/fxkVwiUuvvouqf6X5VBqw5qCFxnE5Qt4w3oYCWqYxN3Xu5r\nj1iU9BV2VEfc2FhCBk056QKBgQDChm/tKy6K9QrmgzQ80XwI6ug9P1U/0thpnqyE\nGWd+OlwzOFDUVGwO+9PqzgJwXFsTyabirDhte+Ok8HEOZowh6T2g1/x9sFfTsgkq\nSgXJ9wymX9As138sQbx+nr7GupBNbhKjAZObzBV8X01AOlTAZsp/HW1xuRnBTiIp\n8Tt8cQKBgQDUv6Jpe1/kO0YJ6KlqVcMIZa+aQFamoMavlCNxxBvjoPnVdWB9PtWi\narzVMyAVvTjnT1QvGPJj1dffE+GSrAf3mssdp/tGfMGcgSB0DRcE1jz/JlzEc81F\no9Ki1lCw8ljoaNfJ8K+7wdiQ1V/H+rgL691P/2ZGc4vdOXJvy/hGZA==\n-----END RSA PRIVATE KEY-----")
	if err != nil {
		t.Fatal("generating key blob failed")
	}

	TestJWK := []byte(`{"keys":[{"e":"AQAB","key_ops":["encrypt"],"kid":"Nvhfuq2cCIOAB8XR4Xi9Pr0NP_9CeMzWQGtW_HALz_w","kty":"RSA","n":"v965SRmyp8zbG5eNFuDCmmiSeaHpujG2bC_keLSuzvDMLO1WyrUJveaa5bzMoO0pA46pXkmbqHisozVzpiNDLCo6d3z4TrGMeFPf2APIMu-RSrzN56qvHVyIr5caWfHWk-FMRDwAefyNYRHkdYYkgmFK44hhUdtlCAKEv5UQpFZjvh4iI9jVBdGYMyBaKQLhjI5WIh-QG6Za5sSuOCFMnmuyuvN5DflpLFz595Ss-EoBIY-Nil6lCtvcGgR-IbjUYHAOs5ajamTzgeO8kx3VCE9HcyKmyUZsiyiF6IDRp2Bpy3NHTjIz7tmkpTHx7tHnRtlfE2FUv0B6i_QYl_ZA5Q"}]}`)

	// this test passes as the jwkey blob created from PEM matches the expected one
	t.Run("SKR_KeyBlobFromPEM", func(t *testing.T) {
		if !bytes.Equal(TestJWK, TestKeyBlobBytes) {
			t.Fatalf("expected %q got %q", string(TestJWK), string(TestKeyBlobBytes))
		}
	})
}
