// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package filemanager

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// The reference file format is a file full of zeroes with 32-bit offset stamps
// every kilobyte. For example:
//
// Address    || Offset stamp      || Padding
// -----------++-------------------++--------------
// 0x00000000 || 00 | 00 | 00 | 00 || 00 | 00 | ...
// 0x00012400 || 00 | 01 | 24 | 00 || 00 | 00 | ...
// 0x34567800 || 34 | 56 | 78 | 00 || 00 | 00 | ...

func referenceFileSize() int64 {
	return 256*GetBlockSize() - 1024
}

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
		if (realOffset % 1024) == 0 {
			data[i] = byte(realOffset >> 24)
		} else if (realOffset % 1024) == 1 {
			data[i] = byte((realOffset - 1) >> 16)
		} else if (realOffset % 1024) == 2 {
			data[i] = byte((realOffset - 2) >> 8)
		} else if (realOffset % 1024) == 3 {
			data[i] = byte(realOffset - 3)
		} else {
			data[i] = 0
		}
	}
	return data
}

func GenerateReferenceFile(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrapf(err, "failed to open file")
	}
	defer file.Close()

	var offset int64 = 0
	for {
		data := []byte{byte(offset >> 24), byte(offset >> 16), byte(offset >> 8), byte(offset)}

		_, err = file.Seek(offset, os.SEEK_SET)
		if err != nil {
			return errors.Wrapf(err, "failed to seek in file")
		}

		_, err = file.Write(data)
		if err != nil {
			return errors.Wrapf(err, "failed to write in file")
		}
		offset = offset + 1024

		if offset == referenceFileSize() {
			break
		}
	}

	file.Truncate(referenceFileSize())

	return nil
}

// Test reading different ranges of bytes from the file. None of them should
// cross a block boundary.
func Test_GetBytes_Supported(t *testing.T) {
	ClearCache()

	VerifyReadRange := func(t *testing.T, offset int64, size int64) {
		err, data := GetBytes(offset, offset+size)
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

	var baseOffset int64

	// Block 0
	baseOffset = 0
	VerifyReadRange(t, baseOffset+32*1024, 4)
	VerifyReadRange(t, baseOffset+128*1024, 2500)

	// Block 1
	baseOffset = GetBlockSize()
	VerifyReadRange(t, baseOffset+64*1024, 1000)
	VerifyReadRange(t, baseOffset+512*1024, 1024)

	// Block 5
	baseOffset = 5 * GetBlockSize()
	VerifyReadRange(t, baseOffset+64*1024, 1000)
	VerifyReadRange(t, baseOffset+512*1024, 10000)

	// Block 12
	baseOffset = 12 * GetBlockSize()
	VerifyReadRange(t, baseOffset+64*1024, 1000)
	VerifyReadRange(t, baseOffset+512*1024, 10000)

	// Get bytes from start of the file

	VerifyReadRange(t, 0, 100)
	VerifyReadRange(t, 0, 10000)

	// Get bytes from end of the file

	VerifyReadRange(t, referenceFileSize()-100, 90)
	VerifyReadRange(t, referenceFileSize()-100, 99)
	VerifyReadRange(t, referenceFileSize()-100, 100)

	// Try to get more bytes than available (the resulting slice should be
	// smaller than the requested size)

	VerifyReadRange(t, referenceFileSize()-100, 101)
	VerifyReadRange(t, referenceFileSize()-100, 200)
}

// Test that this function fails when trying to get data in ranges that cross a
// block boundary
func Test_GetBytes_Unsupported(t *testing.T) {
	ClearCache()

	GetBytesShouldFail := func(t *testing.T, from int64, to int64) {
		err, _ := GetBytes(from, to)
		if err == nil {
			t.Errorf("GetBytes(%d, %d) should have failed", from, to)
		}
	}

	GetBytesShouldSucceed := func(t *testing.T, from int64, to int64) {
		err, _ := GetBytes(from, to)
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
	GetBytesShouldSucceed(t, GetBlockSize(), 2*GetBlockSize()-1)
	GetBytesShouldSucceed(t, GetBlockSize(), 2*GetBlockSize())
	GetBytesShouldFail(t, GetBlockSize(), 2*GetBlockSize()+1)
	GetBytesShouldFail(t, GetBlockSize()-1, 2*GetBlockSize())
	GetBytesShouldSucceed(t, GetBlockSize(), 2*GetBlockSize())
	GetBytesShouldSucceed(t, GetBlockSize()+1, 2*GetBlockSize())

	// Test bigger sizes than allowed
	GetBytesShouldFail(t, 1*GetBlockSize(), 3*GetBlockSize())
	GetBytesShouldFail(t, 1*GetBlockSize(), (2*GetBlockSize())+1)
}

// Test getting blocks outside of bounds, and the ones right at the limits.
func Test_GetBlock_TestBounds(t *testing.T) {
	ClearCache()

	err, _ := GetBlock(-1)
	if err.Error() != "invalid block index (-1)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
	err, _ = GetBlock(0)
	if err != nil {
		t.Errorf("GetBlock(0) should have succeeded: %s", err.Error())
	}
	err, _ = GetBlock(255)
	if err != nil {
		t.Errorf("GetBlock(255) should have succeeded: %s", err.Error())
	}
	err, _ = GetBlock(256)
	if err.Error() != "block index over limit (256 > 255)" {
		t.Errorf("GetBlock(-1) should have failed")
	}
}

func makeRange(min int64, max int64) []int64 {
	r := make([]int64, max-min+1)
	for i := range r {
		r[i] = min + int64(i)
	}
	return r
}

func getBlocks(r []int64) error {
	for _, index := range r {
		err, data := GetBlock(index)
		if err != nil {
			return errors.Wrapf(err, "GetBlock(%d) failed", index)
		}

		offset := GetBlockSize() * index
		size := GetBlockSize()
		referenceData := GenerateReferenceSlice(offset, size)

		res := bytes.Compare(data, referenceData)
		if res != 0 {
			return errors.New(fmt.Sprintf("GetBlock(%d): comparison failed", index))
		}
	}
	return nil
}

// The tests only test the filemanager cache code. In order for them to run
// faster, the local file reader is setup, no the Azure downloader. The
// TestMain funcion needs to generate a reference file so that the tests can
// run.
func DoAllTests(m *testing.M) int {
	// Setup logger to log to file, and to log everything

	// If the file doesn't exist, create it. If it exists, append to it.
	file, err := os.OpenFile("/tmp/azmount_tests.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logrus.Fatal(err)
		return 1
	}
	defer file.Close()
	logrus.SetOutput(file)

	logrus.SetLevel(logrus.TraceLevel)

	if err := InitializeCache(1024*1024, 32); err != nil {
		fmt.Printf("Failed to initialize cache: %s\n", err.Error())
		return 1
	}

	// Create temporary folder

	tempDir, err := ioutil.TempDir("", "aztemp")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %s\n", err.Error())
		return 1
	}
	defer os.RemoveAll(tempDir) // Remove folder at exit
	fmt.Printf("Temporary directory: %s\n", tempDir)

	// Generate the reference file inside the temporary folder so that it is
	// deleted along the temporary folder at exit

	referenceFile := path.Join(tempDir, "reference_file")

	if err := GenerateReferenceFile(referenceFile); err != nil {
		fmt.Printf("Failed to create reference file: %s\n", err.Error())
		return 1
	}

	if err = LocalSetup(referenceFile); err != nil {
		fmt.Printf("Local filesystem setup error: %s\n", err.Error())
		return 1
	}

	return m.Run()
}

func TestMain(m *testing.M) {
	// All the tests are in DoAllTests() so that al deferred functions are
	// called when returning from there. They aren't called when the program
	// ends because of a call to os.Exit().
	os.Exit(DoAllTests(m))
}
