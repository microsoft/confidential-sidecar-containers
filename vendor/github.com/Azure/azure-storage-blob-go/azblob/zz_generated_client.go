package azblob

// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"net/url"

	"github.com/Azure/azure-pipeline-go/pipeline"
)

const (
	// ServiceVersion specifies the version of the operations used in this package.
	ServiceVersion = "2020-10-02"
)

// managementClient is the base client for Azblob.
type managementClient struct {
	url url.URL
	p   pipeline.Pipeline
}

// newManagementClient creates an instance of the managementClient client.
func newManagementClient(url url.URL, p pipeline.Pipeline) managementClient {
	return managementClient{
		url: url,
		p:   p,
	}
}

// URL returns a copy of the URL for this client.
func (mc managementClient) URL() url.URL {
	return mc.url
}

// Pipeline returns the pipeline for this client.
func (mc managementClient) Pipeline() pipeline.Pipeline {
	return mc.p
}
