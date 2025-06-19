// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

// This tool takes a file stored in Azure Blob Storage in a public container and
// exposes it as a local file at the desired location. The file is downloaded in
// blocks on demand, and it holds a cache of blocks to increase performance.
//
//     mkdir test
//     ./azmount -mountpoint test -url https://testaccount.blob.core.windows.net/public-container/file.txt
//
// To get the size of the file and access its data, for example:
//
//     ls -l test/data
//     cat test/data
//
// It is possible to mount a local file as well, which is useful for testing:
//
//     mkdir test
//     ./azmount -mountpoint test -localpath /path/to/file.txt
import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/Microsoft/confidential-sidecar-containers/cmd/azmount/filemanager"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/sirupsen/logrus"
)

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	mountPoint := flag.String("mountpoint", "", "System path to mount the filesystem to.")
	pageBlobUrl := flag.String("url", "", "URL of page blob with the filesystem to mount.")
	pageBlobPrivate := flag.String("private", "false", "Page blob is private and thus requires credentials")
	encodedIdentity := flag.String("identity", "", "base64-encoded string of identity information")
	localFilePath := flag.String("localpath", "", "Path of a local file with the filesystem to mount.")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")
	blockSize := flag.Int("blocksize", 512, "Size of a cache block in KiB")
	numBlocks := flag.Int("numblocks", 32, "Number of cache blocks")
	readWrite := flag.String("readWrite", "false", "Read-Write file system")

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer func() {
			err := file.Close()
			if err != nil {
				logrus.Fatal(err)
			}
		}()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	parseError := false

	if *mountPoint == "" {
		logrus.Fatal("A mount point is needed\n")
		parseError = true
	}

	if (*pageBlobUrl == "") && (*localFilePath == "") {
		logrus.Fatal("A URL or a local file path is needed\n")
		parseError = true
	}

	if (*pageBlobUrl != "") && (*localFilePath != "") {
		logrus.Fatal("Only one of URL or a local file path must be supplied\n")
		parseError = true
	}

	if *blockSize < 4 {
		logrus.Fatal("The block size must be bigger than 4 KB\n")
		parseError = true
	}

	if (*blockSize % 4) != 0 {
		logrus.Fatal("The block size must be a multiple of 4 KB\n")
		parseError = true
	}

	if *numBlocks < 1 {
		logrus.Fatal("Invalid number of cache blocks\n")
		parseError = true
	}

	pageBlobPrivateBool, err := strconv.ParseBool(*pageBlobPrivate)
	if err != nil {
		logrus.Fatal("The private attribute needs to be true or false")
	}

	readWriteBool, err := strconv.ParseBool(*readWrite)
	if err != nil {
		logrus.Fatal("The readWrite attribute needs to be true or false")
	}

	if parseError {
		usage()
		logrus.Fatal("Invalid arguments")
	}

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Info("Args:")
	logrus.Debugf("   Mountpoint:  %s", *mountPoint)
	logrus.Debugf("   Azure URL:   %s", *pageBlobUrl)
	logrus.Debugf("   Azure URL Private:   %s", *pageBlobPrivate)
	logrus.Debugf("   Encoded Identity Info: %s", *encodedIdentity)
	logrus.Debugf("   Local Path:  %s", *localFilePath)
	logrus.Infof("   Log Level:   %s", *logLevel)
	logrus.Infof("   Log File:    %s", *logFile)
	logrus.Debugf("   Block Size:  %d KiB", *blockSize)
	logrus.Debugf("   Num. Blocks: %d", *numBlocks)
	logrus.Debugf("   ReadWrite:    %s", *readWrite)

	logrus.Info("Initializing cache...")
	if err := filemanager.InitializeCache(*blockSize*1024, *numBlocks, readWriteBool); err != nil {
		logrus.Fatal("Failed to initialize cache: " + err.Error())
	}

	if *pageBlobUrl != "" {
		logrus.Info("Setting up Azure connection...")

		identityBytes, err := base64.StdEncoding.DecodeString(*encodedIdentity)
		if err != nil {
			logrus.Info("Could not decode identity string. Using empty ...")
		}

		identity := common.Identity{}
		err = json.Unmarshal(identityBytes, &identity)
		if err != nil {
			logrus.Infof("Failed to unmarshal identity bytes: %s", err.Error())
		}

		if err = filemanager.AzureSetup(*pageBlobUrl, pageBlobPrivateBool, identity); err != nil {
			logrus.Fatal("Azure connection setup error: " + err.Error())
		}
		logrus.Info("Azure connection set up")
	}

	if *localFilePath != "" {
		logrus.Info("Setting up local filesystem...")
		if err = filemanager.LocalSetup(*localFilePath, readWriteBool); err != nil {
			logrus.Fatal("Local filesystem setup error: " + err.Error())
		}
		logrus.Info("Local filesystem set up")
	}

	logrus.Info("Setting up FUSE...")
	err = FuseSetup(*mountPoint, readWriteBool)
	if err != nil {
		logrus.Fatal("FUSE error: " + err.Error())
	}
	logrus.Info("FUSE ended")
}
