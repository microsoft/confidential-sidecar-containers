// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

const (
	overlayMountLocation = "./overlay"
)

func Test_Keywrap(t *testing.T) {
	type overlayFsTestcase struct {
		name string

		vhdMount     string
		scratchMount string
		overlayMount string

		expectedError error
		expectErr     bool
	}

	vhdMountLocation, err := os.MkdirTemp(".", "vhd")
	if err != nil {
		t.Fatalf("Unable to make temp VHD dir: %v", err)
	}

	scratchMountLocation, err := os.MkdirTemp(".", "scratch")
	if err != nil {
		t.Fatalf("Unable to make temp Scratch dir: %v", err)
	}

	overlayMountPath, err := filepath.Abs(overlayMountLocation)
	if err != nil {
		t.Fatalf("Unable to get Overlay Mount Location absolute path: %v", err)
	}

	overlayFsTestcases := []*overlayFsTestcase{
		// test passes if there are no errors during OverlayFS creation
		{
			name: "OverlayFS_Success",

			vhdMount:     vhdMountLocation,
			scratchMount: scratchMountLocation,
			overlayMount: overlayMountLocation,

			expectedError: nil,
			expectErr:     false,
		},
		// test passes as attempt to create an OverlayFS without a valid vhdMount location, resulting in an error
		{
			name: "OverlayFS_Missing_vhdMount",

			vhdMount:     "/mnt/vhd",
			scratchMount: scratchMountLocation,
			overlayMount: overlayMountLocation,

			expectedError: errors.New(fmt.Sprintf("Failed to create overlay file system: failed to execute mount: mount: %s: special device overlay does not exist.", overlayMountPath)),
			expectErr:     true,
		},
	}

	for _, tc := range overlayFsTestcases {
		t.Run(tc.name, func(t *testing.T) {
			err := MountOverlayFilesystem(tc.vhdMount, tc.scratchMount, tc.overlayMount)

			if tc.expectErr && err == nil {
				t.Fatal("expected err got nil")
			} else if tc.expectErr && !strings.Contains(err.Error(), tc.expectedError.Error()) {
				t.Fatalf("expected %q got %q", tc.expectedError.Error(), err.Error())
			} else if !tc.expectErr && err != nil {
				t.Fatalf("did not expect err got %q", err.Error())
			}
		})
	}
}
