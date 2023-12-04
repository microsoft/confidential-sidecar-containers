#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

keyFilePath=keyfile.bin
encryptedImage=encfs.img
hashDevice=hash.img

cryptDeviceName=cryptdevice1-gen
verityDeviceName=veritydevice1-gen

cryptDeviceNamePath="/dev/mapper/$cryptDeviceName"
verityDeviceNamePath="/dev/mapper/$verityDeviceName"

verity=false

# Parse arguments
for arg in "$@"
do
    case $arg in
        --verity=true)
        verity=true
        shift
        ;;
        --verity=false)
        verity=false
        shift
        ;;
    esac
done

if [ -f "$keyFilePath" ]; then
    echo "keyfile exists"
else
    echo "[!] Generating keyfile..."
    dd if=/dev/urandom of="$keyFilePath" count=1 bs=32
fi

echo "Key in hex string format"

python hexstring.py $keyFilePath

truncate -s 32 "$keyFilePath"

echo "[!] Creating encrypted image..."

rm -f "$encryptedImage"
truncate --size 64M "$encryptedImage"

sudo cryptsetup luksFormat --type luks2 "$encryptedImage" \
    --key-file "$keyFilePath" -v --batch-mode --sector-size 4096 \
    --cipher aes-xts-plain64 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000

if [ "$verity" = true ]; then
    sudo cryptsetup luksOpen "$encryptedImage" "$cryptDeviceName" \
        --key-file "$keyFilePath" \
        --persistent
else
    sudo cryptsetup luksOpen "$encryptedImage" "$cryptDeviceName" \
        --key-file "$keyFilePath" \
        --integrity-no-journal --persistent
fi

echo "[!] Formatting as ext4..."

sudo mkfs.ext4 "$cryptDeviceNamePath"

echo "[!] Mounting..."

mountPoint=`mktemp -d`
sudo mount -t ext4 "$cryptDeviceNamePath" "$mountPoint" -o loop

echo "[!] Copying contents to encrypted device..."

# The /* is needed to copy folder contents instead of the folder + contents
sudo cp -r filesystem/* "$mountPoint"
ls "$mountPoint"

echo "[!] Closing device..."

sudo umount "$mountPoint"

sudo cryptsetup luksClose "$cryptDeviceName"

# setup dm-verity data and hash device if --verity=true
if [ "$verity" = true ]; then
  rm -f "$hashDevice"
  sudo veritysetup -v --debug format $encryptedImage $hashDevice | grep 'Root hash:' | tail -c 65 | head -c 64 > root_hash
fi