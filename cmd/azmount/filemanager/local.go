// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"io"
	"os"

	"github.com/pkg/errors"
)

func LocalSetup(filePath string, readWrite bool) error {
	var file *os.File
	var err error
	if readWrite {
		file, err = os.OpenFile(filePath, os.O_RDWR, 0)
	} else {
		file, err = os.OpenFile(filePath, os.O_RDONLY, 0)
	}
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", filePath)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return errors.Wrapf(err, "failed to stat file: %s", filePath)
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
	bytesInBlock := GetBlockSize()
	var offset int64 = blockIndex * bytesInBlock
	var count int64 = bytesInBlock

	file, err := os.OpenFile(fm.filePath, os.O_RDONLY, 0)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "failed to open file: %s", fm.filePath), empty
	}
	defer file.Close()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "failed to seek file: %s", fm.filePath), empty
	}

	data := make([]byte, count)
	_, err = file.Read(data)
	if err != nil {
		var empty []byte
		return errors.Wrapf(err, "failed to read source file"), empty
	}

	return err, data
}

func LocalUploadBlock(blockIndex int64, data []byte) error {
	bytesInBlock := GetBlockSize()
	var offset int64 = blockIndex * bytesInBlock

	file, err := os.OpenFile(fm.filePath, os.O_RDWR, 0)
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", fm.filePath)
	}
	defer file.Close()

	_, err = file.Seek(offset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "failed to seek file: %s", fm.filePath)
	}

	_, err = file.Write(data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to file")
	}

	return nil
}
