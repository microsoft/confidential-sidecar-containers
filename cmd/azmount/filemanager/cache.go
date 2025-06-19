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
	downloadBlock func(blockIndex int64) ([]byte, error)

	// Function used to write block to raw filesystem image
	uploadBlock func(blockIndex int64, data []byte) error

	// Read-Write cache
	readWrite bool
}

// Global state of the file manager
var fm FileManager

func onEvict(key interface{}, value interface{}) {
	blockIndex := key.(int64)
	bytes, ok := value.(*[]byte)
	if !ok {
		panic(fmt.Errorf("cast failed for block"))
	}

	err := fm.uploadBlock(blockIndex, *bytes)
	if err != nil {
		panic(errors.Wrapf(err, "Can't upload block %d", blockIndex))
	}
}

func InitializeCache(blockSize int, numBlocks int, readWrite bool) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	var cache *lru.Cache
	var err error

	if readWrite {
		cache, err = lru.NewWithEvict(numBlocks, onEvict)
	} else {
		cache, err = lru.New(numBlocks)
	}

	if err != nil {
		return errors.Wrap(err, "Failed to initialize RAM cache")
	}
	fm.cache = cache
	fm.readWrite = readWrite
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

func IsReadWrite() bool {
	return fm.readWrite
}

// Utility function to check if the block is in the cache and get it if it is
func GetBlockFromCache(blockIndex int64) ([]byte, error) {
	i, ok := fm.cache.Get(blockIndex)
	if ok {
		bytes, ok := i.(*[]byte)
		if !ok {
			return nil, fmt.Errorf("GetBlockFromCache: cast to bytes failed for block %d", blockIndex)
		}
		return *bytes, nil
	}
	return nil, nil
}

// Utility function to download the block
func DownloadBlock(blockIndex int64) ([]byte, error) {
	dat, err := fm.downloadBlock(blockIndex)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "Can't download block")
	}
	return dat, nil
}

func GetBlock(blockIndex int64) ([]byte, error) {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// Check bounds
	if blockIndex < 0 {
		errorString := fmt.Sprintf("Invalid block index (%d)", blockIndex)
		return []byte{}, errors.New(errorString)
	}

	maxIndex := (fm.contentLength - 1) / fm.blockSize
	if blockIndex > maxIndex {
		errorString := fmt.Sprintf("Block index over limit (%d > %d)", blockIndex, maxIndex)
		return []byte{}, errors.New(errorString)
	}

	// Check if this block is in the cache
	dat, err := GetBlockFromCache(blockIndex)
	if err != nil {
		return []byte{}, err
	}
	// If it isn't in the cache, download it
	if dat == nil {
		dat, err = DownloadBlock(blockIndex)
		if err != nil {
			return []byte{}, err
		}
	}

	// Save data to the cache
	fm.cache.Add(blockIndex, &dat)

	return dat, err
}

func GetBytes(offset int64, to int64) ([]byte, error) {
	if offset < 0 || to < 0 {
		errorString := fmt.Sprintf("GetBytes(%d, %d): negative pointer", offset, to)
		return []byte{}, errors.New(errorString)
	}

	// If going over the end of the file, return fewer bytes than requested
	if to > fm.contentLength {
		to = fm.contentLength
	}

	// The end must go after the start
	if offset > to {
		errorString := fmt.Sprintf("GetBytes(%d, %d): invalid pointers", offset, to)
		return []byte{}, errors.New(errorString)
	}
	// This function is always asked to read 4KB aligned to a 4KB boundary, so
	// there is never a risk of having to cross block boundaries. However,
	// check that this is actually true in case that changes in the future.
	startBlockIndex := offset / fm.blockSize
	endBlockIndex := (to - 1) / fm.blockSize
	if startBlockIndex != endBlockIndex {
		errorString := fmt.Sprintf("GetBytes(%d, %d): unsupported", offset, to)
		return []byte{}, errors.New(errorString)
	}

	blockIndex := offset / fm.blockSize
	offsetInsideBlock := offset - (blockIndex * fm.blockSize)
	toInsideBlock := to - (blockIndex * fm.blockSize)

	dat, err := GetBlock(blockIndex)
	if err != nil {
		return []byte{}, err
	}
	return dat[offsetInsideBlock:toInsideBlock], err
}

func SetBlock(blockIndex int64, blockOffset int64, data []byte) error {
	fm.mutex.Lock()
	defer fm.mutex.Unlock()

	// Check bounds
	if blockIndex < 0 {
		errorString := fmt.Sprintf("Invalid block index (%d)", blockIndex)
		return errors.New(errorString)
	}

	maxIndex := (fm.contentLength - 1) / fm.blockSize
	if blockIndex > maxIndex {
		errorString := fmt.Sprintf("Block index over limit (%d > %d)", blockIndex, maxIndex)
		return errors.New(errorString)
	}

	// Check if this block is in the cache
	dat, err := GetBlockFromCache(blockIndex)
	if err != nil {
		return err
	}
	// If it isn't in the cache, download it
	if dat == nil {
		dat, err = DownloadBlock(blockIndex)
		if err != nil {
			return err
		}
	}
	content := &dat

	copy((*content)[blockOffset:], data)
	fm.cache.Add(blockIndex, content)

	return err
}

func SetBytes(offset int64, data []byte) error {
	if offset < 0 {
		errorString := fmt.Sprintf("SetBytes(%d): negative pointer", offset)
		return errors.New(errorString)
	}

	var to = offset + int64(len(data))

	// If going over the end of the file, write fewer bytes than requested
	if to > fm.contentLength {
		to = fm.contentLength
	}

	// The end must go after the start
	if offset > to {
		errorString := fmt.Sprintf("SetBytes(%d, %d): invalid pointers", offset, to)
		return errors.New(errorString)
	}

	// This function is always asked to write 4KB aligned to a 4KB boundary, so
	// there is never a risk of having to cross block boundaries. However,
	// check that this is actually true in case that changes in the future.
	startBlockIndex := offset / fm.blockSize
	endBlockIndex := (to - 1) / fm.blockSize
	if startBlockIndex != endBlockIndex {
		errorString := fmt.Sprintf("SetBytes(%d, %d): unsupported", offset, to)
		return errors.New(errorString)
	}
	blockIndex := offset / fm.blockSize
	offsetInsideBlock := offset - (blockIndex * fm.blockSize)

	// get number of bytes to write
	numBytesToWrite := to - offset

	return SetBlock(blockIndex, offsetInsideBlock, data[:numBytesToWrite])
}
