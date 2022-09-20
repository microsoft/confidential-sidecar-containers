// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"os"

	"github.com/pkg/errors"
)

func LocalSetup(filePath string) error {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
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

	_, err = file.Seek(offset, os.SEEK_SET)
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

	return nil, data
}
