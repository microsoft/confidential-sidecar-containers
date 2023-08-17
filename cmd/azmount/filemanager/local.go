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
		logrus.Info("Opening file for read/write")
		file, err = os.OpenFile(filePath, os.O_RDWR, 0)
	} else {
		logrus.Info("Opening file for read only")
		file, err = os.OpenFile(filePath, os.O_RDONLY, 0)
	}
	if err != nil {
		return errors.Wrapf(err, "Failed to open file: %s", filePath)
	}
	defer file.Close()

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

	return nil
}

func LocalDownloadBlock(blockIndex int64) (err error, b []byte) {
	logrus.Info("Downloading block...")
	bytesInBlock := GetBlockSize()
	var offset int64 = blockIndex * bytesInBlock
	logrus.Infof("Block offset %d = block index %d * bytes in blck %d", offset, blockIndex, bytesInBlock)
	var count int64 = bytesInBlock

	file, err := os.OpenFile(fm.filePath, os.O_RDONLY, 0)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "Failed to open file: %s", fm.filePath), empty
	}
	defer file.Close()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "Failed to seek file: %s", fm.filePath), empty
	}

	data := make([]byte, count)
	_, err = file.Read(data)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "Failed to read source file: %s", fm.filePath), empty
	}

	return err, data
}

func LocalUploadBlock(blockIndex int64, data []byte) error {
	logrus.Info("Uploading block...")
	bytesInBlock := GetBlockSize()
	var offset int64 = blockIndex * bytesInBlock
	logrus.Infof("Block offset %d = block index %d * bytes in blck %d", offset, blockIndex, bytesInBlock)

	file, err := os.OpenFile(fm.filePath, os.O_RDWR, 0)
	if err != nil {
		return errors.Wrapf(err, "Failed to open file: %s", fm.filePath)
	}
	defer file.Close()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "Failed to seek file: %s", fm.filePath)
	}

	_, err = file.Write(data)
	if err != nil {
		return errors.Wrapf(err, "Failed to write to file: %s", fm.filePath)
	}

	return nil
}
