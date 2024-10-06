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

var previewLock sync.Mutex

func main() {
	previewerPath := flag.String("previewer", "", "Path to the previewer executable")
	previewTimeoutStr := flag.String("preview-timeout", "20s", "Timeout for the previewer")
	flag.Parse()

	previewerTimeout, err := time.ParseDuration(*previewTimeoutStr)
	if err != nil {
		panic(err)
	}

	if *previewerPath == "" {
		panic("previewer path is required")
	}

	http.HandleFunc("/preview", previewHandler(*previewerPath, previewerTimeout))

	log.Println("Listening")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func previewHandler(previewerPath string, previewerTimeout time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		previewLock.Lock()
		defer previewLock.Unlock()

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

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

		fwFile, err := loadFirmware(ctx, r.URL.Query().Get("fw"))
		if err != nil {
			log.Printf("failed to load firmware: %v", err)

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cancel()
		defer os.Remove(fwFile.Name())

		ctx, cancel = context.WithTimeout(r.Context(), previewerTimeout)
		defer cancel()

		screenshotFile, err := os.CreateTemp("/tmp", "*")
		if err != nil {
			log.Printf("failed to create temp file: %v", err)

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer os.Remove(screenshotFile.Name())
		defer screenshotFile.Close()

		cmd := exec.CommandContext(ctx, previewerPath, "-screenshot", screenshotFile.Name(), fwFile.Name(), "/dev/stdin")
		cmd.Stdin = strings.NewReader(script)
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			log.Printf("failed to run previewer: %v", err)

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, err := screenshotFile.Seek(0, 0); err != nil {
			log.Printf("failed to seek to start of file: %v", err)

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")

		if _, err := io.Copy(w, screenshotFile); err != nil {
			log.Printf("failed to copy file to response: %v", err)

			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
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
