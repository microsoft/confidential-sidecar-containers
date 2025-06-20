// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package common

import (
	"bytes"
	"io"
	"net/http"

	"github.com/pkg/errors"
)

type HTTPError struct {
	Status string
}

func (e HTTPError) Error() string {
	return "http response status equal to " + e.Status
}

func httpClientDoRequest(req *http.Request) (*http.Response, error) {
	httpClientDoWrapper := func() (interface{}, error) {
		client := &http.Client{}
		return client.Do(req)
	}

	resp, err := httpClientDoWrapper()

	if err != nil {
		return nil, errors.Wrapf(err, "HTTP GET failed")
	}

	return resp.(*http.Response), nil
}

func HTTPGetRequest(uri string, metadata bool) (*http.Response, error) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "http get request creation failed")
	}

	if metadata {
		req.Header.Add("Metadata", "true")
	}

	return httpClientDoRequest(req)
}

func HTTPPRequest(httpType string, uri string, jsonData []byte, authorizationToken string) (*http.Response, error) {
	if httpType != "POST" && httpType != "PUT" {
		return nil, errors.Errorf("invalid http request")
	}

	req, err := http.NewRequest(httpType, uri, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrapf(err, "http post request creation failed")
	}

	req.Header.Set("Content-Type", "application/json")
	if authorizationToken != "" {
		req.Header.Add("Authorization", "Bearer "+authorizationToken)
	}

	return httpClientDoRequest(req)
}

func HTTPResponseBody(httpResponse *http.Response) ([]byte, error) {
	// Pull out response body. We are using a LimitReader to prevent unlimited server response causing buffer overflow
	var httpResponseBodyBytes []byte
	var err error
	if httpResponse != nil && httpResponse.Body != nil {
		defer func() {
			err = httpResponse.Body.Close()
			if err != nil {
				err = errors.Wrapf(err, "Failed to close HTTP response body\n")
			}
		}()
		respLen := httpResponse.ContentLength
		// 134MB is an arbitrary limit size that is appropriate for http response using bit manipulation
		const respLenLimit134mb = 1 << 20
		if respLen < 1 || respLen > respLenLimit134mb {
			respLen = respLenLimit134mb
		}
		httpResponseBodyBytes, _ = io.ReadAll(io.LimitReader(httpResponse.Body, int64(respLen)))
	}
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 207 {
		return nil, errors.Wrap(&HTTPError{httpResponse.Status}, string(httpResponseBodyBytes))
	}
	return httpResponseBodyBytes, err
}
