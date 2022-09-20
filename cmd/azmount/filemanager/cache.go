// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-storage-blob-go/azblob"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type FileManager struct {
	// Context objects to access data from Azure Blob Storage
	ctx     context.Context
	blobURL azblob.PageBlobURL

	// Objects to access data from local storage
	filePath string

	// The maximum size for a page blob is 8 TB
	contentLength int64

	// Cache handler
	cache     *lru.Cache
	blockSize int64

	// Mutex for the block cache
	mutex sync.Mutex

	// Function used to access a block from the raw filesystem image
	downloadBlock func(blockIndex int64) (error, []byte)
}

// Global state of the file manager
var fm FileManager

func InitializeCache(blockSize int, numBlocks int) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	cache, err := lru.New(numBlocks)
	if err != nil {
		return errors.Wrap(err, "failed to initialize RAM cache")
	}
	fm.cache = cache

	fm.blockSize = int64(blockSize)

	return nil
}

// This clears cache. It is only needed for testing purposes.
func ClearCache() error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	fm.cache.Purge()

	return nil
}

func GetFileSize() int64 {
	return fm.contentLength
}

func GetBlockSize() int64 {
	return fm.blockSize
}

func GetBlock(blockIndex int64) (error, []byte) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// Check bounds
	if blockIndex < 0 {
		errorString := fmt.Sprintf("invalid block index (%d)", blockIndex)
		return errors.New(errorString), []byte{}
	}

	maxIndex := (fm.contentLength - 1) / fm.blockSize
	if blockIndex > maxIndex {
		errorString := fmt.Sprintf("block index over limit (%d > %d)", blockIndex, maxIndex)
		return errors.New(errorString), []byte{}
	}

	// Check if this block is in the cache
	i, ok := fm.cache.Get(blockIndex)
	if ok {
		bytes, ok := i.(*[]byte)
		if !ok {
			return fmt.Errorf("cast failed for block %d", blockIndex), nil
		}
		return nil, *bytes
	}

	// If it isn't in the cache, download it
	err, dat := fm.downloadBlock(blockIndex)
	if err != nil {
		return errors.Wrapf(err, "can't download block"), []byte{}
	}

	logrus.Tracef("Fetched block %d", blockIndex)

	// Save data to the cache
	fm.cache.Add(blockIndex, &dat)

	return nil, dat
}

func GetBytes(offset int64, to int64) (error, []byte) {
	if offset < 0 || to < 0 {
		errorString := fmt.Sprintf("GetBytes(%d, %d): negative pointer", offset, to)
		return errors.New(errorString), []byte{}
	}

	// If going over the end of the file, return fewer bytes than requested
	if to > fm.contentLength {
		to = fm.contentLength
	}

	// The end must go after the start
	if offset > to {
		errorString := fmt.Sprintf("GetBytes(%d, %d): invalid pointers", offset, to)
		return errors.New(errorString), []byte{}
	}

	// This function is always asked to read 4KB aligned to a 4KB boundary, so
	// there is never a risk of having to cross block boundaries. However,
	// check that this is actually true in case that changes in the future.
	startBlockIndex := offset / fm.blockSize
	endBlockIndex := (to - 1) / fm.blockSize
	if startBlockIndex != endBlockIndex {
		errorString := fmt.Sprintf("GetBytes(%d, %d): unsupported", offset, to)
		return errors.New(errorString), []byte{}
	}

	blockIndex := offset / fm.blockSize
	offsetInsideBlock := offset - (blockIndex * fm.blockSize)
	toInsideBlock := to - (blockIndex * fm.blockSize)

	err, dat := GetBlock(blockIndex)
	return err, dat[offsetInsideBlock:toInsideBlock]
}
