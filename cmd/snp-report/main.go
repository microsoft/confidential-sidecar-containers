// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
)

func main() {
	fetcher, err := attest.NewAttestationReportFetcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating attestation report fetcher: %v\n", err)
		os.Exit(1)
	}

	reportData := [attest.REPORT_DATA_SIZE]byte{}
	reportBytes, err := fetcher.FetchAttestationReportByte(reportData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching attestation report: %v\n", err)
		os.Exit(1)
	}

	report := attest.SNPAttestationReport{}
	if err := report.DeserializeReport(reportBytes); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing attestation report: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling attestation report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
}
