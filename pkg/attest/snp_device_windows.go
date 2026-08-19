// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

package attest

import "github.com/sirupsen/logrus"

func IsSNPVM() bool {
	_, err := NewAttestationReportFetcher()
	if err != nil {
		logrus.Errorf("IsSNPVM: returning false due to failure initializing attestation report fetcher: %v", err)
	}
	return err == nil
}
