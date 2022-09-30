// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
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
	curentTokenFields := strings.Split(currentToken, ".")
	payload, _ := base64.StdEncoding.DecodeString(curentTokenFields[1])
	var payloadMap map[string]interface{}
	json.Unmarshal([]byte(payload), &payloadMap)
	audience := payloadMap["aud"].(string)

	identity := common.Identity{
		ClientId: payloadMap["appid"].(string),
	}

	// retrieve token using the existing's token audience
	refreshToken, err := common.GetToken(audience, identity)

	if err != nil {
		return 0
	}
	// Duration expects nanosecond count
	ExpiresInSeconds, err := strconv.ParseInt(refreshToken.ExpiresIn, 10, 64)
	if err != nil {
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
	logrus.Infof("Connecting to Azure...")
	u, err := url.Parse(urlString)
	if err != nil {
		return errors.Wrapf(err, "can't parse URL string")
	}

	if urlPrivate {
		// we use token credentials to access private azure blob storage the blob's
		// url Host denotes the scope/audience for which we need to get a token
		logrus.Infof("Using token credentials")

		var token common.TokenResponse
		count := 0
		for {
			token, err = common.GetToken("https://"+u.Host, identity)

			if err != nil {
				logrus.Infof("can't obtain a token rquired for accessing private blobs. will retry in case the ACI identity sidecar is not running yet.")
				time.Sleep(3 * time.Second)
				count++
				if count == 20 {
					return errors.Wrapf(err, "timeout of 60 seconds expired. could not obtained token")
				}
			} else {
				logrus.Infof("token obtained. continuing")
				break
			}
		}

		tokenCredential := azblob.NewTokenCredential(token.AccessToken, tokenRefresher)
		fm.blobURL = azblob.NewPageBlobURL(*u, azblob.NewPipeline(tokenCredential, azblob.PipelineOptions{}))
	} else {
		// we can use anonymous credentials to access public azure blob storage
		logrus.Infof("Using anonymous credentials")

		anonCredential := azblob.NewAnonymousCredential()
		fm.blobURL = azblob.NewPageBlobURL(*u, azblob.NewPipeline(anonCredential, azblob.PipelineOptions{}))
	}

	// Use a never-expiring context
	fm.ctx = context.Background()
	logrus.Infof("Getting size of file...")

	// Get file size
	getMetadata, err := fm.blobURL.GetProperties(fm.ctx, azblob.BlobAccessConditions{},
		azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return errors.Wrapf(err, "can't get size")
	}
	fm.contentLength = getMetadata.ContentLength()
	logrus.Infof("Size: %d bytes", fm.contentLength)

	// Setup data downloader
	fm.downloadBlock = AzureDownloadBlock

	return nil
}

func AzureDownloadBlock(blockIndex int64) (err error, b []byte) {
	bytesInBlock := GetBlockSize()
	var offset int64 = blockIndex * bytesInBlock
	var count int64 = bytesInBlock

	get, err := fm.blobURL.Download(fm.ctx, offset, count, azblob.BlobAccessConditions{},
		false, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "can't download block"), empty
	}

	blobData := &bytes.Buffer{}
	reader := get.Body(azblob.RetryReaderOptions{})
	_, err = blobData.ReadFrom(reader)
	// The client must close the response body when finished with it
	reader.Close()

	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "ReadFrom() failed"), empty
	}

	return nil, blobData.Bytes()
}
