// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

func usage() {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	vhdMount := flag.String("vhdmount", "", "location of the mounted VHD")
	scratchMount := flag.String("scratchmount", "", "location of the mounted scratch space")
	overlayMount := flag.String("overlaymount", "", "location to mount the overlay file system")
	logLevel := flag.String("loglevel", "warning", "Logging Level: trace, debug, info, warning, error, fatal, panic.")
	logFile := flag.String("logfile", "", "Logging Target: An optional file name/path. Omit for console output.")

	flag.Usage = usage

	flag.Parse()

	if *logFile != "" {
		// If the file doesn't exist, create it. If it exists, append to it.
		file, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		defer file.Close()
		logrus.SetOutput(file)
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.SetLevel(level)
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: false, DisableQuote: true, DisableTimestamp: true})

	logrus.Infof("Starting %s...", os.Args[0])

	logrus.Infof("Args:")
	logrus.Infof("   Log Level: %s", *logLevel)
	logrus.Infof("   Log File:  %s", *logFile)
	logrus.Debugf("   vhdMount:    %s", *vhdMount)
	logrus.Debugf("   scratchMount:    %s", *scratchMount)
	logrus.Debugf("   overlayMount:    %s", *overlayMount)

	err = MountOverlayFilesystem(*vhdMount, *scratchMount, *overlayMount)
	if err != nil {
		logrus.Fatalf("Failed to mount filesystems: %s", err.Error())
	}

	os.Exit(0)
}
