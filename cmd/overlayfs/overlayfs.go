// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux
// +build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// mountCommand runs mount with the provided arguments
func mountCommand(args []string) error {
	logrus.Debugf("Executing mount with args: %v", args)
	cmd := exec.Command("mount", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to execute mount: %s", string(output))
	}
	return nil
}

// mountOverlay runs "mount -t overlay overlay" with the right arguments.
func mountOverlay(vhdMount string, scratchMount string, workDir string, overlayMount string) error {
	openArgs := []string{
		// mount an overlay filesystem
		"-t overlay overlay",
		// with vhdMount as the lowerdir/ro
		"-olowerdir=" + vhdMount +
			// scratchMount as the upperdir/rw
			",upperdir=" + scratchMount +
			// workDir as the workdir
			",workdir=" + workDir,
		// overlayMount as the mount point
		overlayMount}

	return mountCommand(openArgs)
}

func MountOverlayFilesystem(vhdMount string, scratchMount string, overlayMount string) (err error) {
	logrus.Info("Creating temporary directory to use as workdir for overlayfs")
	// workdir must be an empty dir in the same filesystem as the upperdir/rw
	scratchRootDir, _ := filepath.Split(scratchMount)

	tempDir, err := os.MkdirTemp(scratchRootDir, "workdir")
	if err != nil {
		logrus.Fatalf("Failed to create temp dir: %s", err.Error())
	}
	logrus.Infof("Temporary directory: %s", tempDir)

	logrus.Infof("Mounting RO layer %s, RW layer %s to Overlay File System at %s", vhdMount, scratchMount, overlayMount)
	err = mountOverlay(vhdMount, scratchMount, tempDir, overlayMount)
	if err != nil {
		logrus.Fatalf("Failed to create overlay file system: %s", err.Error())
	}

	return nil
}
