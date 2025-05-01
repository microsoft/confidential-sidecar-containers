The ```azmount``` tool exposes a file located in Azure Blob Storage as a local file.
For example, the tool can be used like this:

```
mkdir /tmp/test
azmount -url https://samplename.blob.core.windows.net/public-container/image-encrypted.img -mountpoint /tmp/test
```

This will result in a file: ``/tmp/test/data``, which contains the contents of the file from Azure Blob Storage.

Alternatively, it can also mount a local file for testing purposes:

```
mkdir /tmp/test
azmount -localpath /home/example/myfile -mountpoint /tmp/test
```

``azmount`` will keep running until the user does:

```
unmount /tmp/test
```

The way the program works is:

- It uses FUSE to expose the remote file as a local file.

- Whenever the program gets a read request from the kernel, it checks if that part of the file is in the local cache of blocks.
  If it isn't, it fetches it from Azure Blob Storage and saves it to the cache.

  It is necessary to keep a local cache because the kernel tends to do lots of small reads of a few KB in size rather than big reads, which has a big performance cost.

Other command line options are:

- ``loglevel``: Specify the log level.
- ``logfile``: Specify a path to use as log file instead of directing the log
  output to stdout.
- ``blocksize``: Size of a cache block in KiB.
- ``numblocks``: Number of cache blocks to keep.
- ``readWrite``: Specify if the filesystem is read-write (true) or read-only (false or not included)
