// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package attest

import (
	"os"

	"github.com/pkg/errors"
)

const SNP_DEVICE_PATH_5 = "/dev/sev"
const SNP_DEVICE_PATH_6 = "/dev/sev-guest"

// Check if the code is being run in SNP VM for Linux kernel version 5.x.
func IsSNPVM5() bool {
	_, err := os.Stat(SNP_DEVICE_PATH_5)
	return !errors.Is(err, os.ErrNotExist)
}

// Check if the code is being run in SNP VM for Linux kernel version 6.x.
func IsSNPVM6() bool {
	_, err := os.Stat(SNP_DEVICE_PATH_6)
	return !errors.Is(err, os.ErrNotExist)
}

func IsSNPVM() bool {
	return IsSNPVM5() || IsSNPVM6()
}
