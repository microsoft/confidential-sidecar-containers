// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux
// +build linux

package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"strings"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"golang.org/x/crypto/hkdf"
)

// Test dependencies
var (
	_azmountRun                    = azmountRun
	_containerMountAzureFilesystem = containerMountAzureFilesystem
	_cryptsetupOpen                = cryptsetupOpen
	_veritysetupFormat             = veritysetupFormat
	_veritysetupOpen               = veritysetupOpen
	ioutilWriteFile                = ioutil.WriteFile
	osGetenv                       = os.Getenv
	osMkdirAll                     = os.MkdirAll
	osRemoveAll                    = os.RemoveAll
	osStat                         = os.Stat
	osCreate                       = os.Create
	timeSleep                      = time.Sleep
	unixMount                      = unix.Mount
)

var (
	Identity              common.Identity
	CertState             attest.CertState
	EncodedUvmInformation common.UvmInformation
	// for testing encrypted filesystems without releasing secrets from
	// AKV allowTestingWithRawKey needs to be set to true and a raw key
	// needs to have been provided. Default mode is that such testing is
	// disabled.
	allowTestingWithRawKey = false
)

// Constant
// offset of "Roothash:"
const ROOTHASH_OFFSET int = 9
// length of roothash
const ROOTHASH_LENGTH int = 64

// azmountRun starts azmount with the specified arguments, and leaves it running
// in the background.
func azmountRun(imageLocalFolder string, azureImageUrl string, azureImageUrlPrivate bool, azmountLogFile string, cacheBlockSize string, numBlocks string) error {

	identityJson, err := json.Marshal(Identity)
	if err != nil {
		logrus.Debugf("failed to marshal identity...")
		return err
	}

	encodedIdentity := base64.StdEncoding.EncodeToString(identityJson)

	logrus.Debugf("Starting azmount: %s %s %s %s %s KB", imageLocalFolder, azureImageUrl, strconv.FormatBool(azureImageUrlPrivate), azmountLogFile, cacheBlockSize)
	cmd := exec.Command("/bin/azmount", "-mountpoint", imageLocalFolder, "-url", azureImageUrl, "-private", strconv.FormatBool(azureImageUrlPrivate), "-identity", encodedIdentity, "-logfile", azmountLogFile, "-blocksize", cacheBlockSize, "-numblocks", numBlocks)
	if err := cmd.Start(); err != nil {
		errorString := "azmount failed to start"
		logrus.WithError(err).Error(errorString)
		return errors.Wrapf(err, errorString)
	}
	logrus.Debugf("azmount running...")
	return nil
}

// cryptsetupCommand runs cryptsetup with the provided arguments
func cryptsetupCommand(args []string) error {
	// --debug and -v are used to increase the information printed by
	// cryptsetup. By default, it doesn't print much information, which makes it
	// hard to debug it when there are problems.
	cmd := exec.Command("cryptsetup", append([]string{"--debug", "-v"}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to execute cryptsetup: %s", string(output))
	}
	return nil
}

// cryptsetupOpen runs "cryptsetup luksOpen" with the right arguments.
func cryptsetupOpen(source string, deviceName string, keyFilePath string) error {
	openArgs := []string{
		// Open device with the key passed to luksFormat
		"luksOpen", source, deviceName, "--key-file", keyFilePath,
		// Don't use a journal to increase performance
		"--integrity-no-journal",
		"--persistent"}

	return cryptsetupCommand(openArgs)
}

// veritysetupCommand runs veritysetup with the provided arguments
func veritysetupCommand(args []string) (string, error) {
	cmd := exec.Command("veritysetup", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "failed to execute veritysetup: %s", string(output))
	}
	return string(output), nil
}

// veritysetupOpen runs "veritysetup open" with right arguments
func veritysetupOpen(dataDevicePath string, dmVerityName string, hashDevicePath string, rootHash string) (string, error) {
	openArgs := []string{
		"open", dataDevicePath, dmVerityName, hashDevicePath, rootHash}
	return veritysetupCommand(openArgs)
}

// veritysetupFormat runs "veritysetup format" with right arguments
func veritysetupFormat(dataDevicePath string, hashDevicePath string) (string, error) {
	openArgs := []string{
		"format", dataDevicePath, hashDevicePath}
	return veritysetupCommand(openArgs)
}

// extract root hash from the veritysetup output
func getRootHash(formatOutput string) (string, error) {
	if len(formatOutput) < ROOTHASH_OFFSET + ROOTHASH_LENGTH {
		return "", errors.New("Index Out of Bound")
	}
	// remove space and escape sequences
	replacer := strings.NewReplacer(" ","", "\n", "", "\t", "")
	replacedString := replacer.Replace(formatOutput)
	index := strings.Index(replacedString,"Roothash:")
	if index < 0 {
		return "", errors.New("Incorrect Format Output")
	}
	rootHash := replacedString[index+ROOTHASH_OFFSET : index+ROOTHASH_OFFSET+ROOTHASH_LENGTH]
	return rootHash, nil
}

// store root hash for future verification
func storeRootHash(rootHash string, mountPoint string, index int) error {
	rootHashPath, err := filepath.Abs(filepath.Join(mountPoint, fmt.Sprintf("../.dm-verity-root-hash-%d", index)))
	if err != nil {
		return errors.Wrapf(err, "failed to resolve absolute path of root hash file")
	}
	rootHashFile, err := osCreate(rootHashPath)
	if err != nil {
		return errors.Wrapf(err, "failed to create root hash file")
	}
	defer func(){
		err := rootHashFile.Close()
		if err != nil {
			logrus.WithError(err).Debugf("failed to close root hash file: %s", rootHashPath)
		} else {
			logrus.Debugf("Close root hash file: %s", rootHashPath)
		}
	}()
	_, err = rootHashFile.WriteString(rootHash)
	if err != nil {
		return errors.Wrapf(err, "failed to write root hash")
	}
	return nil
}

func mountAzureFile(tempDir string, index int, azureImageUrl string, azureImageUrlPrivate bool, cacheBlockSize string, numBlocks string) (string, error) {

	imageLocalFolder := filepath.Join(tempDir, fmt.Sprintf("%d", index))
	if err := osMkdirAll(imageLocalFolder, 0755); err != nil {
		return "", errors.Wrapf(err, "mkdir failed: %s", imageLocalFolder)
	}

	// Location in the UVM of the encrypted filesystem image.
	imageLocalFile := filepath.Join(imageLocalFolder, "data")

	// Location of log file generated by azmount
	azmountLogFile := filepath.Join(tempDir, fmt.Sprintf("log-%d.txt", index))

	// Any program that sets up a FUSE filesystem becomes a server that listens
	// to requests from the kernel, and it gets stuck in the loop that serves
	// requests, so it is needed to run it in a different process so that the
	// execution can continue in this one.
	_azmountRun(imageLocalFolder, azureImageUrl, azureImageUrlPrivate, azmountLogFile, cacheBlockSize, numBlocks)

	// Wait until the file is available
	count := 0
	for {
		_, err := osStat(imageLocalFile)
		if err == nil {
			// Found
			break
		}
		// Timeout after 10 seconds
		count++
		if count == 1000 {
			return "", errors.New("timed out")
		}
		timeSleep(60 * time.Millisecond)
	}
	logrus.Debugf("Found file")

	return imageLocalFile, nil
}

// rawRemoteFilesystemKey sets up the key file path using the raw key passed
func rawRemoteFilesystemKey(tempDir string, rawKeyHexString string) (keyFilePath string, err error) {

	keyFilePath = filepath.Join(tempDir, "keyfile")

	keyBytes := make([]byte, 64)

	keyBytes, err = hex.DecodeString(rawKeyHexString)
	if err != nil {
		logrus.WithError(err).Debugf("failed to decode raw key: %s", rawKeyHexString)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	// dm-crypt expects a key file, so create a key file using the key released in
	// previous step
	err = ioutilWriteFile(keyFilePath, keyBytes, 0644)
	if err != nil {
		logrus.WithError(err).Debugf("failed to delete keyfile: %s", keyFilePath)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	return keyFilePath, nil
}

// releaseRemoteFilesystemKey releases the key identified by keyBlob from AKV
//
// 1) Retrieve encoded  security policy by reading the environment variable
//
// 2) Perform secure key release
//
// 3) Prepare the key file path using the released key
func releaseRemoteFilesystemKey(tempDir string, keyDerivationBlob skr.KeyDerivationBlob, keyBlob skr.KeyBlob) (keyFilePath string, err error) {

	keyFilePath = filepath.Join(tempDir, "keyfile")

	if EncodedUvmInformation.EncodedSecurityPolicy == "" {
		err = errors.New("EncodedSecurityPolicy is empty")
		logrus.WithError(err).Debugf("Make sure the environment is correct") // only helpful running outside of a UVM
		return "", err
	}

	// 2) release key identified by keyBlob using encoded security policy and certfetcher (contained in CertState object)
	//    certfetcher is required for validating the attestation report against the cert
	//    chain of the chip identified in the attestation report
	jwKey, err := skr.SecureKeyRelease(Identity, CertState, keyBlob, EncodedUvmInformation)
	if err != nil {
		logrus.WithError(err).Debugf("failed to release key: %v", keyBlob)
		return "", errors.Wrapf(err, "failed to release key")
	}
	logrus.Debugf("Key Type: %s", jwKey.KeyType())

	octetKeyBytes := make([]byte, 32)
	var rawKey interface{}
	err = jwKey.Raw(&rawKey)
	if err != nil {
		logrus.WithError(err).Debugf("failed to extract raw key")
		return "", errors.Wrapf(err, "failed to extract raw key")
	}

	if jwKey.KeyType() == "oct" {
		rawOctetKeyBytes, ok := rawKey.([]byte)
		if !ok || len(rawOctetKeyBytes) != 32 {
			logrus.WithError(err).Debugf("expected 32-byte octet key")
			return "", errors.Wrapf(err, "expected 32-byte octet key")
		}
		octetKeyBytes = rawOctetKeyBytes
	} else if jwKey.KeyType() == "RSA" {
		rawKey, ok := rawKey.(*rsa.PrivateKey)
		if !ok {
			logrus.WithError(err).Debugf("expected RSA key")
			return "", errors.Wrapf(err, "expected RSA key")
		}
		// use sha256 as hashing function for HKDF
		hash := sha256.New

		// public salt and label
		var labelString string
		if keyDerivationBlob.Label != "" {
			labelString = keyDerivationBlob.Label
		} else {
			labelString = "Symmetric Encryption Key"
		}

		// decode public salt hexstring
		salt, err := hex.DecodeString(keyDerivationBlob.Salt)
		if err != nil {
			logrus.WithError(err).Debugf("failed to decode salt hexstring")
			return "", errors.Wrapf(err, "failed to decode salt hexstring")
		}

		// setup derivation function using secret D exponent, salt, and label
		hkdf := hkdf.New(hash, rawKey.D.Bytes(), salt, []byte(labelString))

		// derive key
		if _, err := io.ReadFull(hkdf, octetKeyBytes); err != nil {
			logrus.WithError(err).Debugf("failed to derive oct key")
			return "", errors.Wrapf(err, "failed to derive oct key")
		}

		logrus.Debugf("Symmetric key %s (salt: %s label: %s)", hex.EncodeToString(octetKeyBytes), keyDerivationBlob.Salt, labelString)
	} else {
		logrus.WithError(err).Debugf("key type %snot supported", jwKey.KeyType())
		return "", errors.Wrapf(err, "key type %s not supported", jwKey.KeyType())
	}

	// 3) dm-crypt expects a key file, so create a key file using the key released in
	//    previous step
	err = ioutilWriteFile(keyFilePath, octetKeyBytes, 0644)
	if err != nil {
		logrus.WithError(err).Debugf("failed to delete keyfile: %s", keyFilePath)
		return "", errors.Wrapf(err, "failed to write keyfile")
	}

	return keyFilePath, nil
}

// containerMountAzureFilesystem mounts a remote filesystems specified in the
// policy of a given container.
//
//  1. Get the actual filesystem image. This is done by starting a new azmount
//     process. The file is then exposed at “/[tempDir]/[index]/data“ and the
//     log of azmount is saved to “/[tempDir]/log-[index].txt“.
//
//  2. Obtain keyfile. This is hardcoded at the moment and needs to be replaced
//     by the actual code that gets the key. It is saved to a temporary file so
//     that it can be passed to cryptsetup. It can be removed afterwards.
//
//  3. Open encrypted filesystem with cryptsetup. The result is a block device in
//     “/dev/mapper/remote-crypt-[filesystem-index]“.
//
//  4. Config dm-verity on /dev/mapper/remote-crypt-[filesystem-index]
//
//  5. Mount block device as a read-only filesystem.
//
//  6. Create a symlink to the filesystem in the path shared between the UVM and
//     the container.
func containerMountAzureFilesystem(tempDir string, index int, fs AzureFilesystem) (err error) {

	cacheBlockSize := "512"
	numBlocks := "32"

	// 1) Mount remote image
	imageLocalFile, err := mountAzureFile(tempDir, index, fs.AzureUrl, fs.AzureUrlPrivate, cacheBlockSize, numBlocks)
	if err != nil {
		return errors.Wrapf(err, "failed to mount remote file: %s", fs.AzureUrl)
	}

	// 2) Obtain keyfile

	var keyFilePath string
	if fs.KeyBlob.KID != "" {
		keyFilePath, err = releaseRemoteFilesystemKey(tempDir, fs.KeyDerivationBlob, fs.KeyBlob)
		if err != nil {
			return errors.Wrapf(err, "failed to obtain keyfile")
		}
	} else if allowTestingWithRawKey {
		keyFilePath, err = rawRemoteFilesystemKey(tempDir, fs.RawKeyHexString)
		if err != nil {
			return errors.Wrapf(err, "failed to obtain keyfile")
		}
	}

	defer func() {
		// Delete keyfile on exit
		if inErr := osRemoveAll(keyFilePath); inErr != nil {
			logrus.WithError(inErr).Debugf("failed to delete keyfile: %s", keyFilePath)
		} else {
			logrus.Debugf("Deleted keyfile: %s", keyFilePath)
		}
	}()

	// 3) Open encrypted filesystem with cryptsetup. The result is a block
	// device in /dev/mapper/remote-crypt-[filesystem-index] so that it is
	// unique from all other filesystems.
	var deviceName = fmt.Sprintf("remote-crypt-%d", index)
	var deviceNamePath = "/dev/mapper/" + deviceName

	err = _cryptsetupOpen(imageLocalFile, deviceName, keyFilePath)
	if err != nil {
		return errors.Wrapf(err, "luksOpen failed: %s", deviceName)
	}
	logrus.Debugf("Device opened: %s", deviceName)

	// 4) Config the decrypted filesystem in dm-verity format
	hashDeviceName := fmt.Sprintf("hash-device-%d", index)
	hashDevicePath := "/dev/mapper/" + hashDeviceName
	verityDeviceName := fmt.Sprintf("remote-verity-%d", index)
	verityDevicePath := "/dev/mapper/" + verityDeviceName
	// format dm-verity
	formatOutput, err := veritysetupFormat(deviceNamePath, hashDevicePath)
	if err != nil {
		return errors.Wrapf(err, "Failed to Format dm-verity Device")
	}
	logrus.Debugf("veritysetup format output message: %s", formatOutput)
	// get root hash
	rootHash, err := getRootHash(string(formatOutput))
	if err != nil {
		return errors.Wrapf(err, "Wrong dm-verity format output")
	}
	logrus.Debugf("dm-verity root hash: %s", rootHash)
	// open dm-verity device
	openOutput, err := veritysetupOpen(deviceNamePath, verityDeviceName, hashDevicePath, rootHash)
	if err != nil {
		return errors.Wrapf(err, "Fail to open dm-verity device")
	}
	logrus.Debugf("veritysetup open output message: %s", openOutput)
	logrus.Debugf("Successfully format and open dm-verity device")
	// store root hash for future verification
	err = storeRootHash(rootHash, fs.MountPoint, index)
	if err != nil {
		return errors.Wrapf(err, "Failed to store root hash as a file")
	}

	// 5) Mount dm-verity block device as a read-only filesystem.
	tempMountFolder, err := filepath.Abs(filepath.Join(fs.MountPoint, fmt.Sprintf("../.filesystem-%d", index)))
	if err != nil {
		return errors.Wrapf(err, "failed to resolve absolute path")
	}

	logrus.Debugf("Mounting to: %s", tempMountFolder)

	var flags uintptr = unix.MS_RDONLY
	data := "noload"

	if err := osMkdirAll(tempMountFolder, 0755); err != nil {
		return errors.Wrapf(err, "mkdir failed: %s", tempMountFolder)
	}

	if err := unixMount(verityDevicePath, tempMountFolder, "ext4", flags, data); err != nil {
		return errors.Wrapf(err, "failed to mount filesystem: %s", verityDevicePath)
	}

	// 6) Create a symlink to the folder where the filesystem is mounted.
	destPath := fs.MountPoint
	logrus.Debugf("Linking to: %s", destPath)

	if err := os.Symlink(fmt.Sprintf(".filesystem-%d", index), destPath); err != nil {
		return errors.Wrapf(err, "failed to symlink filesystem: %s", destPath)
	}

	return nil
}

func MountAzureFilesystems(tempDir string, info RemoteFilesystemsInformation) (err error) {

	Identity = info.AzureInfo.Identity

	// Retrieve the incoming encoded security policy, cert and uvm endorsement
	EncodedUvmInformation, err = common.GetUvmInformation()
	if err != nil {
		logrus.Fatalf("Failed to extract UVM_* environment variables: %s", err.Error())
	}

	logrus.Debugf("EncodedUvmInformation.InitialCerts.Tcbm: %s\n", EncodedUvmInformation.InitialCerts.Tcbm)
	thimTcbm, err := strconv.ParseUint(EncodedUvmInformation.InitialCerts.Tcbm, 16, 64)
	if err != nil {
		logrus.Fatal("Unable to convert Initial Certs TCBM to a uint64")
	}

	CertState = attest.CertState{
		CertFetcher: info.AzureInfo.CertFetcher,
		Tcbm:        thimTcbm,
	}

	for i, fs := range info.AzureFilesystems {
		logrus.Debugf("Mounting Azure Storage blob %d...", i)

		err = _containerMountAzureFilesystem(tempDir, i, fs)
		if err != nil {
			return errors.Wrapf(err, "failed to mount filesystem index %d", i)
		}
	}

	return nil
}
