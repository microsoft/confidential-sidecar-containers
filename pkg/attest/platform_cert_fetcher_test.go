// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	_ "embed"
	"strconv"
	"testing"

	"encoding/hex"

	"github.com/pkg/errors"
)

func Test_CertFetcher(t *testing.T) {
	// Report data for test
	TestSNPReportBytes, _ := hex.DecodeString("03000000020000001f000300000000000100000000000000000000000000000002000000000000000000000000000000000000000100000004000000000018db25000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1aadd911a47eaf71bdbd46cbc78b00509b2dd125231d7a780e10d01947301d12d0ad79ceb0b648b0e6a90d8aa9f6ea24c33a968b6632085353145e8b19a4741a2dab9ba342e13be4fc0d225e889cc1a580000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003fe9ad60c29f0cf78ad864fb3446b08555cdd6ad79fdf8fefcdbcc5649259693ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff04000000000018db1901010000000000000000000000000000000000000000000f92f1d29e384e0ab34a5176b21e72202785010aa2b14d708754471fd2dddb4c728224b848360e8409adbfb428a2b8c5ce87e7f3ab3a6620073ed60dc05ddc2104000000000018db1d3701001d37010004000000000018db00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f19165162891e72d0729049c14b39a4503f514ebfc3884c804e9c0eed456645f6d490abd69278a3c941862751b6577000000000000000000000000000000000000000000000000071ad071466190d22bd2c326d6bd8dc49b3343ce870759db59ce00119e43d6980de9eb16350eb434fcb7fc533d116d090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	var TestSNPReport SNPAttestationReport
	if err := TestSNPReport.DeserializeReport(TestSNPReportBytes); err != nil {
		t.Fatalf("failed to deserialize attestation report")
	}

	ValidEndpointType := "AzCache"
	ValidEndpoint := "thimpft2.thim.azure-test.net"
	ValidTEEType := "SevSnpVM"
	ValidAPIVersion := "api-version=2021-07-22-preview"
	ClientID := "clientId=ConfidentialSidecarContainersTest"
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
				ClientID:     ClientID,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   nil,
			expectErr:       false,
			expectedContent: "-----BEGIN CERTIFICATE-----\nMIIFQzCCAvegAwIBAgIBADBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA\noRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwezEUMBIGA1UECwwL\nRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEL\nMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2VkIE1pY3JvIERldmljZXMxEjAQ\nBgNVBAMMCVNFVi1NaWxhbjAeFw0yNTAxMjMxOTU4MTBaFw0zMjAxMjMxOTU4MTBa\nMHoxFDASBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwL\nU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNy\nbyBEZXZpY2VzMREwDwYDVQQDDAhTRVYtVkNFSzB2MBAGByqGSM49AgEGBSuBBAAi\nA2IABOQgchKoBoHonXQ06xFa3YWn9PwT7lF4NMT6t63B7cQtBIGdZrbp6gmvB+M3\nQE0yzohNKVvG0pISngH3mpCbG6+cyiL/h/otpxDdFjry38slIPGuCJ01V6mUHLQm\nCjDjBKOCARcwggETMBAGCSsGAQQBnHgBAQQDAgEAMBcGCSsGAQQBnHgBAgQKFghN\naWxhbi1CMDARBgorBgEEAZx4AQMBBAMCAQQwEQYKKwYBBAGceAEDAgQDAgEAMBEG\nCisGAQQBnHgBAwQEAwIBADARBgorBgEEAZx4AQMFBAMCAQAwEQYKKwYBBAGceAED\nBgQDAgEAMBEGCisGAQQBnHgBAwcEAwIBADARBgorBgEEAZx4AQMDBAMCARgwEgYK\nKwYBBAGceAEDCAQEAgIA2zBNBgkrBgEEAZx4AQQEQA+S8dKeOE4Ks0pRdrIeciAn\nhQEKorFNcIdURx/S3dtMcoIkuEg2DoQJrb+0KKK4xc6H5/OrOmYgBz7WDcBd3CEw\nQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDAN\nBglghkgBZQMEAgIFAKIDAgEwA4ICAQBFCBEYFim6rVEc6NgXSG/i3xHTZyDcyujM\nFgALJAleDck5K9Lesi4/NDOk08EBMD3Y9HeqvOOWj+mD75CpYQ9n3l+WzAVG9EQC\ngGeGrG6tYFtFsGhsuH6cwsIjvEo457ypKNBk8FEY+RROXKHL0LV6MDNUL138pynC\ni+Lh3UzPQLIe8Md4ssI1nR9PpiDj6ZN5MGRz2+5wz7y0N77WZr8lNTUL+uPXefGY\nWdrzge8/WXa8x6ESuj7pXbEIGGAjYyai/yu5fGKk7TNNxc4XhSQqFJtI9djVX6zE\n9JpCxCoVNYBxwPTpV2vc65Yp/4SMskCtd8RRmRU9e3MQsdqR3tGEvS3y+JEuloIz\n7m1Sw7hIvDe9wuEC5s3ZtwNGga3ZkFPPDey9F326s6eg4doGZJLyOTlk+ujrNYnx\nSgGByvyiYcmdMN71mON4TtmyfseOcsKEk7Bc1ahKexvrhtEAwDFPud7iQsWJeP3I\nYBRSX5tawSTPzBq9eIpIKRneZUd43lXHbY2wQ4rgpV/ZF7m4v4MxKx1+Dmat88GB\nDorPGkEn6WeSyLQjl2xwc/PYKYg4TrvVG0Rf+sUepmgqR5YBQ7EB3SVG59dgiIn+\nejQOpPqFDAC7ZpNwJVl1+RHz+P4kt3M0sBFQ/9+A88VjsLHDk3JrJnGXsaC6VdHo\n6/IArrlF2g==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC\nBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS\nBgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg\nQ2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp\nY2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy\nMTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS\nBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j\nZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG\n9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg\nW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta\n1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2\nSzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0\n60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05\ngmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg\nbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs\n+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi\nQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ\neTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18\nfHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j\nWhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI\nrFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG\nKWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG\nSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI\nAWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel\nETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw\nSTjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK\ndHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq\nzT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp\nKGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e\npmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq\nHnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh\n3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn\nJZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH\nCViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4\nAFZEAwoKCQ==\n-----END CERTIFICATE-----\n",
		},
		// CertFetcher_Invalid_PlatformVersion passes if the uri associated with the requested certificate was not found
		{
			name: "CertFetcher_Invalid_PlatformVersion",
			certFetcher: CertFetcher{
				EndpointType: ValidEndpointType,
				Endpoint:     ValidEndpoint,
				TEEType:      ValidTEEType,
				APIVersion:   ValidAPIVersion,
				ClientID:     ClientID,
			},
			chipID:          ValidChipID,
			platformVersion: 0xdeadbeef,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://%s/SevSnpVM/certificates/%s/deadbeef?%s&%s' failed: GET request failed with status code 404: ", ValidEndpoint, ValidChipID, ValidAPIVersion, ClientID),
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
				ClientID:     ClientID,
			},
			chipID:          "deadbeef",
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://%s/SevSnpVM/certificates/deadbeef/%s?%s&%s' failed: GET request failed with status code 404: ", ValidEndpoint, strconv.FormatUint(ValidPlatformVersion, 16), ValidAPIVersion, ClientID),
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
				ClientID:     ClientID,
			},
			chipID:          ValidChipID,
			platformVersion: ValidPlatformVersion,
			expectedError:   errors.Errorf("pulling certchain response from AzCache URL 'https://%s/InvalidTEEType/certificates/%s/%s?%s&%s' failed: GET request failed with status code 404: ", ValidEndpoint, ValidChipID, strconv.FormatUint(ValidPlatformVersion, 16), ValidAPIVersion, ClientID),
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
				ClientID:     ClientID,
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
