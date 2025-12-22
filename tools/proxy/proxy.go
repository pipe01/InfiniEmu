// This is a small Go HTTP server that allows users to download InfiniTime GitHub Actions artifacts from the WASM InfiniEmu build

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

const githubAPI = "https://api.github.com"

var (
	token    = os.Getenv("GITHUB_TOKEN")
	owner    = os.Getenv("GITHUB_OWNER")
	repo     = os.Getenv("GITHUB_REPO")
	workflow = os.Getenv("GITHUB_WORKFLOW")
	origins  = os.Getenv("ALLOW_ORIGINS")
	port     = os.Getenv("PORT")
)

func main() {
	if token == "" {
		log.Fatal("Missing GITHUB_TOKEN")
	}
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/artifact", cors(artifactHandler))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // allow long downloads
	}

	log.Printf("Artifact server listening on :%s\n", port)
	log.Fatal(server.ListenAndServe())
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origins) // tighten in prod
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func artifactHandler(w http.ResponseWriter, r *http.Request) {
	artifactID, err := strconv.ParseInt(r.URL.Query().Get("artifact_id"), 10, 64)
	if err != nil {
		http.Error(w, "parse artifact id: "+err.Error(), http.StatusBadRequest)
		return
	}

	stream, err := artifactDownload(artifactID)
	if err != nil {
		http.Error(w, "download artifact: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")

	w.WriteHeader(http.StatusOK)
	io.Copy(w, stream)
}

/* ---------- GitHub API helpers ---------- */

func ghRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	return http.DefaultClient.Do(req)
}

func artifactDownload(artifactID int64) (io.ReadCloser, error) {
	url := fmt.Sprintf(
		"%s/repos/%s/%s/actions/artifacts/%d/zip",
		githubAPI, owner, repo, artifactID,
	)

	resp, err := ghRequest(url)
	if err != nil {
		return nil, fmt.Errorf("get github data: %w", err)
	}

	return resp.Body, nil
}
