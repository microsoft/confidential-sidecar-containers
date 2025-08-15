// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/msi"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// tokenRefresher is a function callback passed during the creation of token credentials
// its implementation shall update an expired token with a new token and return the new
// expiring duration.
func tokenRefresher(credential azblob.TokenCredential) (t time.Duration) {

	// we extract the audience from the existing token so that we can set the resource
	// id for retrieving a new (refresh) token  for the same audience.
	currentToken := credential.Token()
	// JWT tokens comprise three fields. the second field is the payload (or claims).
	// we care about the `aud` attribute of the payload
	currentTokenFields := strings.Split(currentToken, ".")
	logrus.Debugf("Current token fields: %v", currentTokenFields)

	payload, err := base64.RawURLEncoding.DecodeString(currentTokenFields[1])
	if err != nil {
		logrus.Errorf("Error decoding base64 token payload: %s", err)
		return 0
	}
	logrus.Debugf("Current token payload: %s", string(payload))

	var payloadMap map[string]interface{}
	err = json.Unmarshal([]byte(payload), &payloadMap)
	if err != nil {
		logrus.Errorf("Error unmarshalling token payload: %s", err)
		return 0
	}
	audience := payloadMap["aud"].(string)

	identity := common.Identity{
		ClientId: payloadMap["appid"].(string),
	}

	// retrieve token using the existing token audience
	logrus.Debugf("Retrieving new token for audience %s and identity %s", audience, identity)
	refreshToken, err := common.GetToken(audience, identity)

	if err != nil {
		logrus.Errorf("Error retrieving token: %s", err)
		return 0
	}

	// Duration expects nanosecond count
	ExpiresInSeconds, err := strconv.ParseInt(refreshToken.ExpiresIn, 10, 64)
	if err != nil {
		logrus.Errorf("Error parsing token expiration to seconds: %s", err)
		return 0
	}
	credential.SetToken(refreshToken.AccessToken)
	return time.Duration(1000 * 1000 * 1000 * ExpiresInSeconds)
}

// For more information about the library used to access Azure:
//
//     https://pkg.go.dev/github.com/Azure/azure-storage-blob-go/azblob

func AzureSetup(urlString string, urlPrivate bool, identity common.Identity) error {
	// Create a ContainerURL object that wraps a blob's URL and a default
	// request pipeline.
	//
	// The pipeline indicates how the outgoing HTTP request and incoming HTTP
	// response is processed. It specifies things like retry policies, logging,
	// deserialization of HTTP response payloads, and more:
	//
	// https://pkg.go.dev/github.com/Azure/azure-storage-blob-go/azblob#hdr-URL_Types
	logrus.Info("Connecting to Azure...")
	u, err := url.Parse(urlString)
	if err != nil {
		return errors.Wrapf(err, "Can't parse URL string %s", urlString)
	}

	if urlPrivate {
		ctx, cancel := context.WithTimeout(context.Background(), msi.WorkloadIdentityRquestTokenTimeout)
		defer cancel()
		accessToken := ""
		var tokenRefresherFunc func(azblob.TokenCredential) (t time.Duration)

		if msi.WorkloadIdentityEnabled() {
			tokenRefresherFunc = nil
			logrus.Infof("Requesting token for using workload identity from %s", fmt.Sprintf("https://%s", u.Host))
			accessToken, err = msi.GetAccessTokenFromFederatedToken(ctx, fmt.Sprintf("https://%s", u.Host))
			if err != nil {
				return errors.Wrapf(err, "retrieving authentication token using workload identity failed")
			}
		} else {
			tokenRefresherFunc = tokenRefresher
			// we use token credentials to access private azure blob storage the blob's
			// url Host denotes the scope/audience for which we need to get a token
			logrus.Trace("Using token credentials to access private azure blob storage...")

			var token common.TokenResponse
			count := 0
			logrus.Debugf("Getting token for https://%s", u.Host)
			for {
				token, err = common.GetToken("https://"+u.Host, identity)

				if err != nil {
					logrus.Info("Can't obtain a token required for accessing private blobs. Will retry in case the ACI identity sidecar is not running yet...")
					time.Sleep(3 * time.Second)
					count++
					if count == 20 {
						return errors.Wrapf(err, "Timeout of 60 seconds expired. Could not obtain token")
					}
				} else {
					accessToken = token.AccessToken
					break
				}
			}
		}
		tokenCredential := azblob.NewTokenCredential(accessToken, tokenRefresherFunc)
		fm.blobURL = azblob.NewPageBlobURL(*u, azblob.NewPipeline(tokenCredential, azblob.PipelineOptions{}))
		logrus.Debugf("Blob URL created.")
	} else {
		// we can use anonymous credentials to access public azure blob storage
		logrus.Trace("Using anonymous credentials to access public azure blob storage...")

		anonCredential := azblob.NewAnonymousCredential()
		logrus.Debugf("Anonymous credential created: %s", anonCredential)
		fm.blobURL = azblob.NewPageBlobURL(*u, azblob.NewPipeline(anonCredential, azblob.PipelineOptions{}))
		logrus.Debugf("Blob URL created: %s", fm.blobURL)
	}

	// Use a never-expiring context
	fm.ctx = context.Background()

	logrus.Trace("Getting size of file...")
	// Get file size
	getMetadata, err := fm.blobURL.GetProperties(fm.ctx, azblob.BlobAccessConditions{},
		azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return errors.Wrapf(err, "Can't get blob file size")
	}
	fm.contentLength = getMetadata.ContentLength()
	logrus.Tracef("Blob Size: %d bytes", fm.contentLength)

	// Setup data downloader and uploader
	fm.downloadBlock = AzureDownloadBlock
	fm.uploadBlock = AzureUploadBlock

	return nil
}

func AzureUploadBlock(blockIndex int64, b []byte) (err error) {
	logrus.Info("Uploading block...")
	bytesInBlock := GetBlockSize()
	var offset = blockIndex * bytesInBlock
	logrus.Tracef("Block offset %d = block index %d * bytes in block %d", offset, blockIndex, bytesInBlock)

	r := bytes.NewReader(b)
	_, err = fm.blobURL.UploadPages(fm.ctx, offset, r, azblob.PageBlobAccessConditions{},
		nil, azblob.NewClientProvidedKeyOptions(nil, nil, nil))
	if err != nil {
		return errors.Wrapf(err, "Can't upload block")
	}

	return nil
}

func AzureDownloadBlock(blockIndex int64) (b []byte, err error) {
	logrus.Info("Downloading block...")
	bytesInBlock := GetBlockSize()
	var offset = blockIndex * bytesInBlock
	logrus.Tracef("Block offset %d = block index %d * bytes in block %d", offset, blockIndex, bytesInBlock)
	var count = bytesInBlock

	get, err := fm.blobURL.Download(fm.ctx, offset, count, azblob.BlobAccessConditions{},
		false, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "Can't download block")
	}

	blobData := &bytes.Buffer{}
	reader := get.Body(azblob.RetryReaderOptions{})
	_, err = blobData.ReadFrom(reader)
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "ReadFrom() failed for block")
	}
	// The client must close the response body when finished with it
	err = reader.Close()
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "Failure to close reader")
	}

	return blobData.Bytes(), err
}
