// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	"github.com/pkg/errors"
)

const (
	BYTES_PER_KB        = 1024
	BYTES_PER_32KB      = int64(32 * BYTES_PER_KB)
	BYTES_PER_64KB      = int64(64 * BYTES_PER_KB)
	BYTES_PER_128KB     = int64(128 * BYTES_PER_KB)
	BYTES_PER_512KB     = int64(512 * BYTES_PER_KB)
	BLOCK_SIZE          = BYTES_PER_KB * BYTES_PER_KB // 1024^2
	NUM_BLOCKS          = 32
	BASE_OFFSET         = 0
	BLOCK2_OFFSET       = 2 * BLOCK_SIZE
	BLOCK3_OFFSET       = 3 * BLOCK_SIZE
	BLOCK5_OFFSET       = 5 * BLOCK_SIZE
	BLOCK12_OFFSET      = 12 * BLOCK_SIZE
	REFERENCE_FILE_SIZE = 256*BLOCK_SIZE - 1024 // 256*1024^2 - 1024
)

// The reference file format is a file full of zeroes with 32-bit offset stamps
// every kilobyte. For example:
//
// Address    || Offset stamp      || Padding
// -----------++-------------------++--------------
// 0x00000000 || 00 | 00 | 00 | 00 || 00 | 00 | ...
// 0x00012400 || 00 | 01 | 24 | 00 || 00 | 00 | ...
// 0x34567800 || 34 | 56 | 78 | 00 || 00 | 00 | ...

func GenerateReferenceSlice(offset int64, size int64) []byte {
	if size == 0 {
		return []byte{}
	}

	// If going over the end of the file, return less bytes than requested
	if offset+size > fm.contentLength {
		size = fm.contentLength - offset
	}

	data := make([]byte, size)
	for i := int64(0); i < size; i++ {
		realOffset := offset + i
		switch realOffset % BYTES_PER_KB {
		case 0:
			data[i] = byte(realOffset >> 24)
		case 1:
			data[i] = byte((realOffset - 1) >> 16)
		case 2:
			data[i] = byte((realOffset - 2) >> 8)
		case 3:
			data[i] = byte(realOffset - 3)
		default:
			data[i] = 0
		}
	}
	return data
}

func GenerateReferenceFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "failed to create file")
	}
	defer func() {
		err = file.Close()
	}()

	var offset int64 = 0
	for {
		// generate 4 bytes (32 bits) of data
		data := []byte{byte(offset >> 24), byte(offset >> 16), byte(offset >> 8), byte(offset)}

		// move file location to offset
		_, err = file.Seek(offset, io.SeekStart)
		if err != nil {
			return errors.Wrapf(err, "failed to seek in file")
		}

		// every 1KB write 4 bytes of data (will have zeros to fill in the rest of the KB)
		_, err = file.Write(data)
		if err != nil {
			return errors.Wrapf(err, "failed to write in file")
		}
		// increment offset by 1KB
		offset += BYTES_PER_KB

		if offset == REFERENCE_FILE_SIZE {
			break
		}
	}

	err = file.Truncate(REFERENCE_FILE_SIZE)
	if err != nil {
		return errors.Wrapf(err, "failed to truncate file")
	}

	return err
}

func GenerateRandomData(size int64) []byte {
	data := make([]byte, size)
	// Note that no error handling is necessary, as Read always succeeds.
	rand.Read(data) //nolint:errcheck
	return data
}

// Test reading different ranges of bytes from the file. None of them should
// cross a block boundary.
func Test_GetBytes_Supported(t *testing.T) {
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	VerifyReadRange := func(t *testing.T, offset int64, size int64) {
		data, err := GetBytes(offset, offset+size)
		if err != nil {
			t.Errorf("GetBytes(%d, %d) failed: %s", offset, offset+size, err.Error())
			return
		}
		referenceData := GenerateReferenceSlice(offset, size)

		res := bytes.Compare(data, referenceData)
		if res != 0 {
			t.Errorf("GetBytes(%d, %d): comparison failed", offset, offset+size)
		}
	}

	// Block 0
	VerifyReadRange(t, BASE_OFFSET+BYTES_PER_32KB, 4)
	VerifyReadRange(t, BASE_OFFSET+BYTES_PER_128KB, 2500)

	// Block 1
	VerifyReadRange(t, BLOCK_SIZE+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK_SIZE+BYTES_PER_512KB, 1024)

	// Block 5
	VerifyReadRange(t, BLOCK5_OFFSET+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK5_OFFSET+BYTES_PER_512KB, 10000)

	// Block 12
	VerifyReadRange(t, BLOCK12_OFFSET+BYTES_PER_64KB, 1000)
	VerifyReadRange(t, BLOCK12_OFFSET+BYTES_PER_512KB, 10000)

	// Get bytes from start of the file
	VerifyReadRange(t, BASE_OFFSET, 100)
	VerifyReadRange(t, BASE_OFFSET, 10000)

	// Get bytes from end of the file
	endOffset := int64(REFERENCE_FILE_SIZE - 100)
	VerifyReadRange(t, endOffset, 90)
	VerifyReadRange(t, endOffset, 99)
	VerifyReadRange(t, endOffset, 100)

	// Try to get more bytes than available (the resulting slice should be
	// smaller than the requested size)
	VerifyReadRange(t, endOffset, 101)
	VerifyReadRange(t, endOffset, 200)
}

// Test that this function fails when trying to get data in ranges that cross a
// block boundary
func Test_GetBytes_Unsupported(t *testing.T) {
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	GetBytesShouldFail := func(t *testing.T, from int64, to int64) {
		_, err := GetBytes(from, to)
		if err == nil {
			t.Errorf("GetBytes(%d, %d) should have failed", from, to)
		}
	}

	GetBytesShouldSucceed := func(t *testing.T, from int64, to int64) {
		_, err := GetBytes(from, to)
		if err != nil {
			t.Errorf("GetBytes(%d, %d) should have succeeded", from, to)
		}
	}

	// Test negative values
	GetBytesShouldFail(t, -1, 100)
	GetBytesShouldFail(t, 100, -1)

	// Test end of slice before start
	GetBytesShouldFail(t, 100, 50)

	// Test offset values around a block boundary to test for off-by-one
	// errors in the checks.
	GetBytesShouldSucceed(t, BLOCK_SIZE, BLOCK2_OFFSET)
	GetBytesShouldSucceed(t, BLOCK_SIZE, BLOCK2_OFFSET-1)
	GetBytesShouldFail(t, BLOCK_SIZE, BLOCK2_OFFSET+1)
	GetBytesShouldFail(t, BLOCK_SIZE-1, BLOCK2_OFFSET)
	GetBytesShouldSucceed(t, BLOCK_SIZE+1, BLOCK2_OFFSET)

	// Test bigger size than allowed
	GetBytesShouldFail(t, BLOCK_SIZE, BLOCK3_OFFSET)
}

// Test getting blocks outside of bounds, and the ones right at the limits.
func Test_GetBlock_TestBounds(t *testing.T) {
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	_, err = GetBlock(-1)
	if err.Error() != "Invalid block index (-1)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
	_, err = GetBlock(0)
	if err != nil {
		t.Errorf("GetBlock(0) should have succeeded: %s", err.Error())
	}
	_, err = GetBlock(255)
	if err != nil {
		t.Errorf("GetBlock(255) should have succeeded: %s", err.Error())
	}
	_, err = GetBlock(256)
	if err.Error() != "Block index over limit (256 > 255)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
}

// Test writing different ranges of bytes into the cache. None of them should
// cross a block boundary.
func Test_SetBytes_Supported(t *testing.T) {
	if !IsReadWrite() {
		t.Skip("Skipping write test because the cache is read-only")
	}
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	VerifyWriteRange := func(t *testing.T, offset int64, data []byte) {
		err := SetBytes(offset, data)
		if err != nil {
			t.Errorf("SetBytes(%d) failed: %s", offset, err.Error())
			return
		}
		referenceData, _ := GetBytes(offset, offset+int64(len(data)))

		// get slice of data that is same size as referenceData
		// for testing data that is too large to write at the end of the file
		res := bytes.Compare(data[:int64(len(referenceData))], referenceData)
		if res != 0 {
			fmt.Printf("referenceData: %v\n", referenceData)
			fmt.Printf("data: %v\n", data)
			t.Errorf("SetBytes(%d): comparison failed", offset)
		}
	}

	// Block 0
	VerifyWriteRange(t, BYTES_PER_32KB, GenerateRandomData(4))
	VerifyWriteRange(t, BYTES_PER_128KB, GenerateRandomData(2500))

	// Block 1
	VerifyWriteRange(t, BLOCK_SIZE+BYTES_PER_64KB, GenerateRandomData(1000))
	VerifyWriteRange(t, BLOCK_SIZE+BYTES_PER_512KB, GenerateRandomData(1024))

	// Block 5
	VerifyWriteRange(t, BLOCK5_OFFSET+BYTES_PER_64KB, GenerateRandomData(1000))
	VerifyWriteRange(t, BLOCK5_OFFSET+BYTES_PER_512KB, GenerateRandomData(10000))

	// Block 12
	VerifyWriteRange(t, BLOCK12_OFFSET+BYTES_PER_64KB, GenerateRandomData(1000))
	VerifyWriteRange(t, BLOCK12_OFFSET+BYTES_PER_512KB, GenerateRandomData(10000))

	// Set bytes from start of the file
	VerifyWriteRange(t, BASE_OFFSET, GenerateRandomData(100))
	VerifyWriteRange(t, BASE_OFFSET, GenerateRandomData(10000))

	// Set bytes from end of the file
	endOffset := int64(REFERENCE_FILE_SIZE - 100)

	VerifyWriteRange(t, endOffset, GenerateRandomData(90))
	VerifyWriteRange(t, endOffset, GenerateRandomData(99))
	VerifyWriteRange(t, endOffset, GenerateRandomData(100))

	// Try to write more bytes than available (the resulting slice should be
	// smaller than the requested size)
	VerifyWriteRange(t, endOffset, GenerateRandomData(101))
	VerifyWriteRange(t, endOffset, GenerateRandomData(200))
}

// Test that this function fails when trying to write data in ranges that cross a
// block boundary
func Test_SetBytes_Unsupported(t *testing.T) {
	if !IsReadWrite() {
		t.Skip("Skipping write test because the cache is read-only")
	}
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	SetBytesShouldFail := func(t *testing.T, offset int64, data []byte) {
		err := SetBytes(offset, data)
		if err == nil {
			t.Errorf("SetBytes(%d) should have failed", offset)
		}
	}

	SetBytesShouldSucceed := func(t *testing.T, offset int64, data []byte) {
		err := SetBytes(offset, data)
		if err != nil {
			t.Errorf("SetBytes(%d) should have succeeded", offset)
		}
	}

	// Generate random data to write
	dataBlock := GenerateRandomData(BLOCK_SIZE)
	twoDataBlocks := GenerateRandomData(2 * BLOCK_SIZE)
	largeData := GenerateRandomData(REFERENCE_FILE_SIZE + 1)

	// Test negative start index
	SetBytesShouldFail(t, -1, dataBlock)

	// Test data larger than a block
	SetBytesShouldFail(t, 100, largeData)

	// Test offset larger than file
	SetBytesShouldFail(t, REFERENCE_FILE_SIZE+1, dataBlock)

	// Test offset values around a block boundary to test for off-by-one
	// errors in the checks.
	SetBytesShouldSucceed(t, BLOCK_SIZE, dataBlock) // can write up to a block of data
	SetBytesShouldFail(t, BLOCK_SIZE-1, dataBlock)  // crossing a block boundary is not allowed
	SetBytesShouldFail(t, BLOCK_SIZE+1, dataBlock)
	SetBytesShouldFail(t, BLOCK_SIZE, twoDataBlocks)
	SetBytesShouldFail(t, BLOCK_SIZE-1, twoDataBlocks)
	SetBytesShouldFail(t, BLOCK_SIZE+1, twoDataBlocks)
}

// Test setting blocks outside of bounds, and the ones right at the limits.
func Test_SetBlock_TestBounds(t *testing.T) {
	if !IsReadWrite() {
		t.Skip("Skipping write test because the cache is read-only")
	}
	err := ClearCache()
	if err != nil {
		t.Errorf("ClearCache() failed: %s", err.Error())
		return
	}

	// Generate random data to write
	data := GenerateRandomData(BLOCK_SIZE)

	err = SetBlock(-1, 0, data)
	if err.Error() != "Invalid block index (-1)" {
		t.Errorf("SetBlock(-1) should have failed")
	}
	err = SetBlock(0, 0, data)
	if err != nil {
		t.Errorf("SetBlock(0) should have succeeded: %s", err.Error())
	}
	err = SetBlock(255, 0, data)
	if err != nil {
		t.Errorf("SetBlock(255) should have succeeded: %s", err.Error())
	}
	err = SetBlock(256, 0, data)
	if err.Error() != "Block index over limit (256 > 255)" {
		t.Errorf("SetBlock(-1) should have failed")
	}
}

// The tests only test the filemanager cache code. In order for them to run
// faster, the local file reader is setup, not the Azure downloader. The
// TestMain funcion needs to generate a reference file so that the tests can
// run.
func DoAllTests(m *testing.M, readWrite bool) {
	if err := InitializeCache(BLOCK_SIZE, NUM_BLOCKS, readWrite); err != nil {
		fmt.Printf("Failed to initialize cache: %s\n", err.Error())
	}

	// Create temporary folder
	tempDir, err := os.MkdirTemp("", "aztemp")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %s\n", err.Error())
	}
	defer func() {
		err := os.RemoveAll(tempDir) // Remove folder at exit
		if err != nil {
			fmt.Printf("Failed to remove tempDir: %s\n", err.Error())
		}
	}()
	fmt.Printf("Temporary directory: %s\n", tempDir)

	// Generate the reference file inside the temporary folder so that it is
	// deleted along the temporary folder at exit
	referenceFile := path.Join(tempDir, "reference_file")

	if err := GenerateReferenceFile(referenceFile); err != nil {
		fmt.Printf("Failed to create reference file: %s\n", err.Error())
	}

	if err = LocalSetup(referenceFile, readWrite); err != nil {
		fmt.Printf("Local filesystem setup error: %s\n", err.Error())
	}

	m.Run()
}

func TestMain(m *testing.M) {
	// test read-write cache
	DoAllTests(m, true)
	// test read-only cache
	DoAllTests(m, false)
}
