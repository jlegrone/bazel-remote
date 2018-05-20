package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/buchgr/bazel-remote/cache"
	"github.com/buchgr/bazel-remote/utils"
)

func TestProxyRead(t *testing.T) {
	expectedData := []byte("hello world")
	hash := sha256.Sum256(expectedData)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(expectedData)
	}))

	cacheDir := testutils.TempDir(t)
	defer os.RemoveAll(cacheDir)
	diskCache := cache.NewDiskCache(cacheDir, 100)

	baseURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Error(err)
	}

	proxy := NewHTTPProxyCache(baseURL, diskCache, &http.Client{}, testutils.NewSilentLogger(),
		testutils.NewSilentLogger())

	cacheKey := hex.EncodeToString(hash[:])

	if diskCache.Contains(cacheKey, false) {
		t.Fatalf("Expected the local cache to be empty")
	}

	readBytes, actualSizeBytes, err := proxy.Get(cacheKey, false)
	if err != nil {
		t.Fatalf("Failed to get the blob via the http proxy: '%v'", err)
	}

	actualData, err := ioutil.ReadAll(readBytes)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(actualData, expectedData) != 0 {
		t.Fatalf("Expected '%v' but received '%v", actualData, expectedData)
	}

	if actualSizeBytes != int64(len(expectedData)) {
		t.Fatalf("Expected '%d' bytes of expected data, but received '%d'", actualSizeBytes,
			len(expectedData))
	}

	if !diskCache.Contains(cacheKey, false) {
		t.Fatalf("The blob has not been cached locally")
	}
}
