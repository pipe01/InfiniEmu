package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	previewLock    sync.Mutex
	previewTimeout time.Duration
	previewerPath  string
)

func main() {
	flag.StringVar(&previewerPath, "previewer", "", "Path to the previewer executable")
	flag.DurationVar(&previewTimeout, "preview-timeout", 20*time.Second, "Timeout for the previewer")
	flag.Parse()

	if previewerPath == "" {
		panic("previewer path is required")
	}

	http.HandleFunc("/preview", func(w http.ResponseWriter, r *http.Request) {
		fwSpecifiers, ok := r.URL.Query()["fw"]
		if !ok || len(fwSpecifiers) != 1 {
			http.Error(w, "missing or multiple 'fw' query parameters", http.StatusBadRequest)
			return
		}

		var script string

		if v, ok := r.URL.Query()["script"]; !ok {
			http.Error(w, "missing or multiple 'script' query parameters", http.StatusBadRequest)
			return
		} else {
			script = strings.Join(v, "\n")
		}

		w.Header().Set("Content-Type", "image/png")

		if err := previewHandler(r.Context(), w, fwSpecifiers[0], script); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Println("Listening")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func previewHandler(ctx context.Context, rw io.Writer, fwSpecifier string, script string) error {
	previewLock.Lock()
	defer previewLock.Unlock()

	fwctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fwFile, err := loadFirmware(fwctx, fwSpecifier)
	if err != nil {
		return fmt.Errorf("load firmware: %w", err)
	}
	cancel()
	defer os.Remove(fwFile.Name())

	prctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()

	screenshotFile, err := os.CreateTemp("/tmp", "*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(screenshotFile.Name())
	defer screenshotFile.Close()

	cmd := exec.CommandContext(prctx, previewerPath, "-screenshot", screenshotFile.Name(), fwFile.Name(), "/dev/stdin")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run previewer: %w", err)
	}

	if _, err := screenshotFile.Seek(0, 0); err != nil {
		return fmt.Errorf("seek to beginning of screenshot file: %w", err)
	}

	if _, err := io.Copy(rw, screenshotFile); err != nil {
		return fmt.Errorf("write screenshot: %w", err)
	}

	return nil
}

func loadFirmware(ctx context.Context, specifier string) (*os.File, error) {
	if prIDStr, ok := strings.CutPrefix(specifier, "pr-"); ok {
		prID, err := strconv.Atoi(prIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PR ID: %v", err)
		}

		return getPullRequestArtifact(ctx, prID)
	}

	if strings.HasPrefix(specifier, "heads/") || strings.HasPrefix(specifier, "tags/") {
		return getRefArtifact(ctx, specifier)
	}

	return getSHACommitArtifact(ctx, specifier)
}
