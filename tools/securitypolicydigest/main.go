// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

/*
	This tool computes the sha-256 digest of the security policy.
	The input is already base64 encoded as that is required for the ARM template/API
	so taking that format is more convenient.
*/

func main() {
	// variables declaration
	var encodedSecurityPolicy string
	var verbose bool
	var filename string

	// flags declaration using flag package
	flag.StringVar(&encodedSecurityPolicy, "p", "", "Security policy in base64-encoded string format")
	flag.StringVar(&filename, "f", "", "file containing security policy in base64-encoded string format")
	flag.BoolVar(&verbose, "v", false, "print the decoded security policy")
	flag.Parse()

	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(1)
	}

	if len(filename) != 0 {
		if len(encodedSecurityPolicy) != 0 {
			fmt.Println("Cannot specify both -p and -f")
			flag.Usage()
			os.Exit(1)
		}
		encodedSecurityPolicyBytes, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("Could not decode file %s\n", filename)
			os.Exit(1)
		}
		encodedSecurityPolicy = string(encodedSecurityPolicyBytes)
	}

	inittimeDataBytes, err := base64.StdEncoding.DecodeString(encodedSecurityPolicy)
	if err != nil {
		fmt.Println("Could not decode: base64 encoding (Std, with padding) required")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("inittimeData %s\n", string(inittimeDataBytes))
	}

	h := sha256.New()
	h.Write(inittimeDataBytes)

	sum := h.Sum(nil)

	if verbose {
		fmt.Printf("inittimeData sha-256 digest %x\n", sum)
	} else {
		fmt.Printf("%x\n", sum)
	}
}
