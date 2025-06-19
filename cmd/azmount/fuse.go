// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"context"
	"os"
	"syscall"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/Microsoft/confidential-sidecar-containers/cmd/azmount/filemanager"
	"github.com/pkg/errors"
)

// For more information about the library used to set up the FUSE filesystem:
//
//     https://github.com/bazil/fuse

func FuseSetup(mountpoint string, readWrite bool) error {

	var c *fuse.Conn
	var err error
	if readWrite {
		c, err = fuse.Mount(
			mountpoint,
			fuse.FSName("azure_filesystem"),
			fuse.Subtype("azurefs"),
		)
	} else {
		c, err = fuse.Mount(
			mountpoint,
			fuse.FSName("azure_filesystem"),
			fuse.Subtype("azurefs"),
			fuse.ReadOnly(),
		)
	}

	if err != nil {
		return errors.Wrapf(err, "Can't start fuse")
	}
	defer func() {
		err = c.Close()
	}()

	// The execution flow stops here. This function is never left until there is
	// a crash or the filesystem is unmounted by the user.
	err = fs.Serve(c, FS{readWrite: readWrite})
	if err != nil {
		return errors.Wrapf(err, "Can't serve fuse")
	}
	return err
}

// FS implements the file system.
type FS struct {
	readWrite bool
}

func (fs FS) Root() (fs.Node, error) {
	//nolint:staticcheck // ignore S1016 as this mimics the example in the bazil/fuse documentation
	return Dir{readWrite: fs.readWrite}, nil
}

// Dir implements both Node and Handle for the root directory.
type Dir struct {
	readWrite bool
}

func (Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0o777
	return nil
}

func (d Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	if name == "data" {
		//nolint:staticcheck // ignore S1016 as this mimics the example in the bazil/fuse documentation
		return File{readWrite: d.readWrite}, nil
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
type File struct {
	readWrite bool
}

func (f File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	if f.readWrite {
		a.Mode = 0o777
	} else {
		a.Mode = 0o444
	}
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

	data, err := filemanager.GetBytes(int64(offset), int64(to))
	resp.Data = data
	return err
}

func (f *File) ReadAll(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (f File) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	if req.Offset < 0 {
		// Before beginning of file.
		return fuse.Errno(syscall.EINVAL)
	}

	offset := uint64(req.Offset)
	fileSize := uint64(filemanager.GetFileSize())

	if offset >= fileSize {
		// Beyond end of file.
		return nil
	}

	to := min(fileSize, offset+uint64(len(req.Data)))
	if to == offset {
		return nil
	}

	err := filemanager.SetBytes(int64(offset), req.Data)
	if err == nil {
		resp.Size = len(req.Data)
	}
	return err
}

func (f File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	err := filemanager.ClearCache()
	if err != nil {
		return errors.Wrapf(err, "Failed to clear cache")
	}
	return err
}
