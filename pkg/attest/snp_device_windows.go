// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

package attest

func IsSNPVM() bool {
	_, err := NewAttestationReportFetcher()
	return err == nil
}
