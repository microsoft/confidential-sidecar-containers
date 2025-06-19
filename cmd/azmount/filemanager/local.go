// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func LocalSetup(filePath string, readWrite bool) error {
	logrus.Info("Setting up local file manager...")
	var file *os.File
	var err error
	if readWrite {
		logrus.Trace("Opening file for read/write")
		file, err = os.OpenFile(filePath, os.O_RDWR, 0)
	} else {
		logrus.Trace("Opening file for read only")
		file, err = os.OpenFile(filePath, os.O_RDONLY, 0)
	}
	if err != nil {
		return errors.Wrapf(err, "Failed to open file: %s", filePath)
	}
	defer func() {
		err = file.Close()
	}()

	fileInfo, err := file.Stat()
	if err != nil {
		return errors.Wrapf(err, "Failed to stat file: %s", filePath)
	}

	fm.contentLength = fileInfo.Size()

	// Save path for later
	fm.filePath = filePath

	// Setup data downloader
	fm.downloadBlock = LocalDownloadBlock

	// Setup data uploader
	fm.uploadBlock = LocalUploadBlock

	return err
}

func LocalDownloadBlock(blockIndex int64) (b []byte, err error) {
	logrus.Info("Downloading block...")
	bytesInBlock := GetBlockSize()
	var offset = blockIndex * bytesInBlock
	logrus.Tracef("Block offset %d = block index %d * bytes in block %d", offset, blockIndex, bytesInBlock)
	var count = bytesInBlock

	file, err := os.OpenFile(fm.filePath, os.O_RDONLY, 0)
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "Failed to open file: %s", fm.filePath)
	}
	defer func() {
		err = file.Close()
	}()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "Failed to seek file: %s", fm.filePath)
	}

	data := make([]byte, count)
	_, err = file.Read(data)
	if err != nil {
		var empty []byte
		return empty, errors.Wrapf(err, "Failed to read source file: %s", fm.filePath)
	}

	return data, err
}

func LocalUploadBlock(blockIndex int64, data []byte) error {
	logrus.Info("Uploading block...")
	bytesInBlock := GetBlockSize()
	var offset = blockIndex * bytesInBlock
	logrus.Tracef("Block offset %d = block index %d * bytes in blck %d", offset, blockIndex, bytesInBlock)

	file, err := os.OpenFile(fm.filePath, os.O_RDWR, 0)
	if err != nil {
		return errors.Wrapf(err, "Failed to open file: %s", fm.filePath)
	}
	defer func() {
		err = file.Close()
	}()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "Failed to seek file: %s", fm.filePath)
	}

	_, err = file.Write(data)
	if err != nil {
		return errors.Wrapf(err, "Failed to write to file: %s", fm.filePath)
	}

	return err
}
