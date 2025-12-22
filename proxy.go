// This is a small Go HTTP server that allows users to download InfiniTime GitHub Actions artifacts from the WASM InfiniEmu build

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const githubAPI = "https://api.github.com"

const (
	infinitimeImageName     = "InfiniTime image"
	infinitimeResourcesName = "InfiniTime resources"
)

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
	mux.HandleFunc("/image", cors(artifactHandler(infinitimeImageName)))
	mux.HandleFunc("/resources", cors(artifactHandler(infinitimeResourcesName)))

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

func artifactHandler(artifactName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		artifactID, err := getArtifactIDFromRequest(r, artifactName)
		if err != nil {
			http.Error(w, "get artifact ID: "+err.Error(), http.StatusInternalServerError)
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
}

func getRunIDFromRequest(r *http.Request) (int64, error) {
	if v := r.URL.Query().Get("run_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse run_id: %w", err)
		}
		return n, nil
	}

	runID, err := latestSuccessfulRun()
	if err != nil {
		return 0, fmt.Errorf("get latest run: %w", err)
	}

	return runID, nil
}

func getArtifactIDFromRequest(r *http.Request, artifactName string) (int64, error) {
	if v := r.URL.Query().Get("artifact_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse artifact_id: %w", err)
		}
		return n, nil
	}

	runID, err := getRunIDFromRequest(r)
	if err != nil {
		return 0, fmt.Errorf("get run ID: %w", err)
	}

	artifact, err := latestArtifact(runID, artifactName)
	if err != nil {
		return 0, fmt.Errorf("get latest artifact: %w", err)
	}

	return artifact.ID, nil
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

func latestSuccessfulRun() (int64, error) {
	url := fmt.Sprintf(
		"%s/repos/%s/%s/actions/workflows/%s/runs?status=success&per_page=1",
		githubAPI, owner, repo, workflow,
	)

	resp, err := ghRequest(url)
	if err != nil {
		return 0, fmt.Errorf("get github data: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Runs []struct {
			ID int64 `json:"id"`
		} `json:"workflow_runs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, fmt.Errorf("decode json: %w", err)
	}

	if len(data.Runs) == 0 {
		return 0, errors.New("no successful workflow runs found")
	}

	return data.Runs[0].ID, nil
}

type Artifact struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func latestArtifact(runID int64, startsWith string) (*Artifact, error) {
	url := fmt.Sprintf(
		"%s/repos/%s/%s/actions/runs/%d/artifacts",
		githubAPI, owner, repo, runID,
	)

	resp, err := ghRequest(url)
	if err != nil {
		return nil, fmt.Errorf("get github data: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Artifacts []Artifact `json:"artifacts"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	for _, a := range data.Artifacts {
		if strings.HasPrefix(a.Name, startsWith) {
			return &a, nil
		}
	}

	return nil, errors.New("no artifact found")
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
