// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	_ "embed"
	"testing"

	"encoding/hex"

	"github.com/pkg/errors"
)

func Test_CertFetcher(t *testing.T) {
	// Report data for test
	TestSNPReportBytes, _ := hex.DecodeString("01000000010000001f00030000000000010000000000000000000000000000000200000000000000000000000000000000000000010000000000000000000031010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a38c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66dd188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000031000000000000000000000000000000000000000000000000e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	var TestSNPReport SNPAttestationReport
	if err := TestSNPReport.DeserializeReport(TestSNPReportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ValidEndpointType := "AzCache"
	ValidEndpoint := "americas.test.acccache.azure.net"
	ValidTEEType := "SevSnpVM"
	ValidAPIVersion := "api-version=2020-10-15-preview"
	ValidChipID := TestSNPReport.ChipID
	ValidPlatformVersion := TestSNPReport.PlatformVersion

	// To-Do: add tests for local THIM endpoints

	type testcase struct {
		name string

		certFetcher CertFetcher

		chipID          string
		platformVersion uint64

		expectedError   error
		expectErr       bool
		expectedContent string
	}

	testcases := []*testcase{
		// CertFetcher_Success passes the testing if it does not receive an error and the certchain mathces the expected content
		{
			name: "CertFetcher_Success",
			certFetcher: CertFetcher{
				EndpointType: ValidEndpointType,
				Endpoint:     ValidEndpoint,
				TEEType:      ValidTEEType,
				APIVersion:   ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   nil,
			expectErr:       false,
			expectedContent: "-----BEGIN CERTIFICATE-----\nMIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD\nVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs\nYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl\nczESMBAGA1UEAwwJU0VWLU1pbGFuMB4XDTIyMDIwOTIxMDYwMFoXDTI5MDIwOTIx\nMDYwMFowejEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYD\nVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk\nIE1pY3JvIERldmljZXMxETAPBgNVBAMMCFNFVi1WQ0VLMHYwEAYHKoZIzj0CAQYF\nK4EEACIDYgAEv8TQmmW1BdCCyeVpj9C6Y2IW3rv3swTxZJNHBYGd9hRvWAyan82O\nCrX4tPiRzxmFRzY7e1RcGWYDhgQw2p8UokXGVz9fKNJKqBMdvEQf7vGUocRHhM83\nJTJrxmq0QxBXo4IBFjCCARIwEAYJKwYBBAGceAEBBAMCAQAwFwYJKwYBBAGceAEC\nBAoWCE1pbGFuLUEwMBEGCisGAQQBnHgBAwEEAwIBADARBgorBgEEAZx4AQMCBAMC\nAQAwEQYKKwYBBAGceAEDBAQDAgEAMBEGCisGAQQBnHgBAwUEAwIBADARBgorBgEE\nAZx4AQMGBAMCAQAwEQYKKwYBBAGceAEDBwQDAgEAMBEGCisGAQQBnHgBAwMEAwIB\nADARBgorBgEEAZx4AQMIBAMCATEwTQYJKwYBBAGceAEEBEDmyGeWzUSwvGt8DU/a\nsz4oB+FLX8RTizdQkhFp2XvPREfH06sqfCX3TBZB4ohcEBHQJcxTb1yaJQRxMTbH\nh39IMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B\nAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBA4ICAQBbwYA2balTK5o3cPAQarZT\ngIRuX4nXWJDHpDJ2YikPK2Te48O49i9r5+1Voza/JauOI+u8h3Rg3fZSCbemLutw\nDzp6vRv9LJOKhy20HcBl2xYKL1zDX2MTnxg2PrHEE++PeMVf4nbhZkbnyfOXE9Ui\nkatdAdpjpSVhIe78c+IipM1rI1weCdRckmPidZHrJvIARYDyUZjHWoqV28O0reaE\nGXPO7k4VyfRh9hBYhwaFyVsAc1yhdU8Fi1jVzXwnyh7xlGfoakIC1oTiv2OF8w8C\nTKir+JXWqndF3BVNK4vMpdCoXO76KELA+gCPOsbbOQ2LMo7ZlwrwrXElFONwyQdi\ncM56hZ7pdGeGe4DoVWQMR/0LJ3b53r90zrvK+2rT65TffeYkt9OUhn5EkCYEGwOI\nb0/f41VTcN2eyh3OUXhucuCsNGCkqSp4sT79W9TOwUHB2oCricjMoLo9nNmdjIWj\nrA0cAae74AbSMmrVEavEdm10zb2lvFshYp5L4reqOqs5DKM+ksKp1u/SsiELYu+i\n3SMDsP/+3eM+7MgJj05rRaGSoYm/mbTUtDl1zZTRVPaW7eQmJBrzClHTd47N+hzD\n/2rJ4hcJnQLVSyYeNxi6zWAv83B95elvyD35CFh8M0L8GjHu+iww3/i6d5rSPLEp\n94cYfdFPuj/5HEjXDN5eww==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\nBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\nBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\nQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\nY2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\nMTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\nBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\nZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\nW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\nSzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\ngmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\nbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\nQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\neTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\nfHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\nWhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\nrFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\nKWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\nSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\nAWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\nETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\nSTjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\ndHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\nzT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\nKGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\npmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\nHnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\nJZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\nCViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\nAFZEAwoKCQ==\n-----END CERTIFICATE-----\n",
		},
		// CertFetcher_Invalid_PlatformVersion passes if the uri associated with the requested certificate was not found
		{
			name: "CertFetcher_Invalid_PlatformVersion",
			certFetcher: CertFetcher{
				EndpointType: ValidEndpointType,
				Endpoint:     ValidEndpoint,
				TEEType:      ValidTEEType,
				APIVersion:   ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: 0xdeadbeef,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://americas.test.acccache.azure.net/SevSnpVM/certificates/e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48/deadbeef?api-version=2020-10-15-preview' failed: GET request failed with status code 404: "),
			expectErr:       true,
		},
		// CertFetcher_Invalid_ChipID passes if the uri associated with the requested certificate was not found
		{
			name: "CertFetcher_Invalid_ChipID",
			certFetcher: CertFetcher{
				EndpointType: ValidEndpointType,
				Endpoint:     ValidEndpoint,
				TEEType:      ValidTEEType,
				APIVersion:   ValidAPIVersion,
			},
			chipID:          "0xdeadbeef",
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://americas.test.acccache.azure.net/SevSnpVM/certificates/0xdeadbeef/3100000000000000?api-version=2020-10-15-preview' failed: GET request failed with status code 404: "),
			expectErr:       true,
		},
		// CertFetcher_Invalid_TEEType passes if the uri associated with the requested tee_type and certificate was not found
		{
			name: "CertFetcher_Invalid_TEEType",
			certFetcher: CertFetcher{
				EndpointType: ValidEndpointType,
				Endpoint:     ValidEndpoint,
				TEEType:      "InvalidTEEType",
				APIVersion:   ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://americas.test.acccache.azure.net/InvalidTEEType/certificates/e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48/3100000000000000?api-version=2020-10-15-preview' failed: GET request failed with status code 404: "),
			expectErr:       true,
		},
		// CertFetcher_Invalid_EndpointType passes if the uri associated with the requested tee_type and certificate was not found
		{
			name: "CertFetcher_Invalid_EndpointType",
			certFetcher: CertFetcher{
				EndpointType: "InvalidEndpointType",
				Endpoint:     ValidEndpoint,
				TEEType:      ValidTEEType,
				APIVersion:   ValidAPIVersion,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("invalid endpoint type: InvalidEndpointType"),
			expectErr:       true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			certchain, _, err := tc.certFetcher.GetCertChain(tc.chipID, tc.platformVersion)

			if tc.expectErr {
				if err == nil {
					t.Fatal("expected err got nil")
				}
				if err.Error() != tc.expectedError.Error() {
					t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("did not expect err got %q", err.Error())
				}
				if string(certchain) != tc.expectedContent {
					t.Fatalf("expected %q got %q", tc.expectedContent, certchain)
				}
			}
		})
	}
}
