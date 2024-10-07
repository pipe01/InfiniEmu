package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const previewCacheDir = "/tmp/preview-cache"

func init() {
	if err := os.MkdirAll(previewCacheDir, 0755); err != nil {
		panic(err)
	}
}

func getCachedPath(job PreviewJob, commitSHA string) string {
	scriptSum := md5.Sum([]byte(job.Script))

	key := fmt.Sprintf("%s-%s-%t", commitSHA, hex.EncodeToString(scriptSum[:]), job.ShowInfo)

	return filepath.Join(previewCacheDir, key)
}

func GetCachedPreview(job PreviewJob, commitSHA string) (io.ReadCloser, bool) {
	path := getCachedPath(job, commitSHA)

	if f, err := os.Open(path); err == nil {
		return f, true
	}

	return nil, false
}

func CachePreview(job PreviewJob, commitSHA string, preview io.Reader) error {
	path := getCachedPath(job, commitSHA)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create cache file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, preview); err != nil {
		return fmt.Errorf("write cache file: %w", err)
	}

	return nil
}
