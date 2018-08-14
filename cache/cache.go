package cache

import (
	"io"
)

// Logger is designed to be satisfied by log.Logger.
type Logger interface {
	Printf(format string, v ...interface{})
}

type CacheErrorCode int

const (
	BlobTooLarge      CacheErrorCode = iota
	ResourceExhausted CacheErrorCode = iota
)

type CacheError struct {
	Code CacheErrorCode
	msg  string
}

func (e *CacheError) Error() string {
	return e.msg
}

// Cache is the interface for a generic blob storage backend. Implementers should handle
// locking internally.
type Cache interface {
	// Put stores a stream of `size` bytes from `r` into the cache. If `expectedSha256` is
	// not the empty string, and the contents don't match it, an error is returned
	Put(key string, size int64, expectedSha256 string, r io.Reader) error
	// Get writes the content of the cache item stored under `key` to `w`. If the item is
	// not found, it returns ok = false.
	Get(key string, actionCache bool) (data io.ReadCloser, sizeBytes int64, err error)
	// Contains returns true if the `key` exists.
	Contains(key string, actionCache bool) (ok bool)
	// MaxSize returns the maximum cache size in bytes.
	MaxSize() int64
	// CurrentSize returns the current cache size in bytes.
	CurrentSize() int64
	// NumItems returns the number of items stored in the cache.
	NumItems() int
}
