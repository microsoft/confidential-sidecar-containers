// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"os"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/microsoft/confidential-sidecars/cmd/azmount/filemanager"
	"github.com/pkg/errors"
)

// For more information about the library used to set up the FUSE filesystem:
//
//     https://github.com/bazil/fuse

func FuseSetup(mountpoint string) error {
	c, err := fuse.Mount(
		mountpoint,
		fuse.FSName("azure_filesystem"),
		fuse.Subtype("azurefs"),
		fuse.ReadOnly(),
	)
	if err != nil {
		return errors.Wrapf(err, "can't start fuse")
	}
	defer c.Close()

	// The execution flow stops here. This function is never left until there is
	// a crash or the filesystem is unmounted by the user.
	err = fs.Serve(c, FS{})
	if err != nil {
		return errors.Wrapf(err, "can't serve fuse")
	}
	return nil
}

// FS implements the file system.
type FS struct{}

func (FS) Root() (fs.Node, error) {
	return Dir{}, nil
}

// Dir implements both Node and Handle for the root directory.
type Dir struct{}

func (Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0o555
	return nil
}

func (Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	if name == "data" {
		return File{}, nil
	}
	return nil, syscall.ENOENT
}

var dirDirs = []fuse.Dirent{
	{Inode: 2, Name: "data", Type: fuse.DT_File},
}

func (Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	return dirDirs, nil
}

// File implements both Node and Handle for the file.
type File struct{}

func (File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	a.Mode = 0o444
	a.Size = uint64(filemanager.GetFileSize())
	return nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (f File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if req.Offset < 0 {
		// Before beginning of file.
		return fuse.Errno(syscall.EINVAL)
	}
	if req.Size == 0 {
		// No bytes requested.
		return nil
	}
	offset := uint64(req.Offset)
	fileSize := uint64(filemanager.GetFileSize())

	if offset >= fileSize {
		// Beyond end of file.
		return nil
	}

	to := min(fileSize, offset+uint64(req.Size))
	if offset == to {
		return nil
	}

	err, data := filemanager.GetBytes(int64(offset), int64(to))
	resp.Data = data
	return err
}
