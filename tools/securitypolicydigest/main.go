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

func main() {
	// variables declaration
	var encodedSecurityPolicy string

	// flags declaration using flag package
	flag.StringVar(&encodedSecurityPolicy, "p", "", "Security policy in base64-encoded string format")
	flag.Parse() // after declaring flags we need to call it

	flag.Parse()
	if flag.NArg() != 0 || len(encodedSecurityPolicy) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	inittimeDataBytes, err := base64.StdEncoding.DecodeString(encodedSecurityPolicy)
	if err != nil {
		fmt.Println("Could not decode ")
		os.Exit(1)
	}

	fmt.Printf("inittimeData %s", string(inittimeDataBytes))

	h := sha256.New()
	h.Write(inittimeDataBytes)

	fmt.Printf("inittimeData sha-256 digest %x", h.Sum(nil))
}
