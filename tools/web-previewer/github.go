package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v66/github"
	"github.com/jellydator/ttlcache/v3"
)

const (
	repositoryOwner    = "InfiniTimeOrg"
	repositoryName     = "InfiniTime"
	workflowFileName   = "main.yml"
	artifactNamePrefix = "InfiniTime image"
)

const firmwareCachePath = "/tmp/firmware-cache"

var gh *github.Client
var ghCache = ttlcache.New[string, string]()

type Artifact struct {
	FirmwareFilePath string
	CommitSHA        string
}

func init() {
	if err := os.MkdirAll(firmwareCachePath, 0755); err != nil {
		panic(err)
	}
}

func isNotFoundError(err error) bool {
	if gerr, ok := err.(*github.ErrorResponse); ok {
		return gerr.Response.StatusCode == http.StatusNotFound
	}

	return false
}

func getPullRequestArtifact(ctx context.Context, id int, noCache bool) (*Artifact, error) {
	key := fmt.Sprintf("pr-%d", id)

	if !noCache && ghCache.Has(key) {
		return getSHACommitArtifact(ctx, ghCache.Get(key).Value(), noCache)
	}

	pr, _, err := gh.PullRequests.Get(ctx, repositoryOwner, repositoryName, id)
	if err != nil {
		if isNotFoundError(err) {
			return nil, PreviewError("pull request not found")
		}

		return nil, fmt.Errorf("list commits: %w", err)
	}

	ghCache.Set(key, *pr.Head.SHA, 5*time.Minute)

	return getSHACommitArtifact(ctx, *pr.Head.SHA, noCache)
}

func getRefArtifact(ctx context.Context, refName string, noCache bool) (*Artifact, error) {
	key := fmt.Sprintf("ref-%s", refName)

	if !noCache && ghCache.Has(key) {
		return getSHACommitArtifact(ctx, ghCache.Get(key).Value(), noCache)
	}

	ref, _, err := gh.Git.GetRef(ctx, repositoryOwner, repositoryName, refName)
	if err != nil {
		if isNotFoundError(err) {
			return nil, PreviewError("ref not found")
		}

		return nil, fmt.Errorf("get ref: %w", err)
	}

	ghCache.Set(key, *ref.Object.SHA, 5*time.Minute)

	return getSHACommitArtifact(ctx, *ref.Object.SHA, noCache)
}

func getSHACommitArtifact(ctx context.Context, sha string, noCache bool) (*Artifact, error) {
	key := fmt.Sprintf("commit-%s", sha)

	var latestID int64

	if !noCache && ghCache.Has(key) {
		latestID, _ = strconv.ParseInt(ghCache.Get(key).Value(), 10, 64)
	} else {
		runs, _, err := gh.Actions.ListWorkflowRunsByFileName(ctx, repositoryOwner, repositoryName, workflowFileName, &github.ListWorkflowRunsOptions{
			HeadSHA: sha,
		})
		if err != nil {
			return nil, fmt.Errorf("list workflow runs: %w", err)
		}

		if len(runs.WorkflowRuns) == 0 {
			return nil, PreviewError(fmt.Sprintf("no workflow runs found for commit '%s'", sha))
		}

		latestID = *slices.MaxFunc(runs.WorkflowRuns, func(a, b *github.WorkflowRun) int {
			at := a.CreatedAt.GetTime()
			bt := b.CreatedAt.GetTime()

			if at.Before(*bt) {
				return -1
			}
			if at.After(*bt) {
				return 1
			}

			return 0
		}).ID

		ghCache.Set(key, fmt.Sprintf("%d", latestID), 15*time.Minute)
	}

	f, err := fetchRunArtifact(ctx, latestID, noCache)
	if err != nil {
		return nil, err
	}

	return &Artifact{
		FirmwareFilePath: f,
		CommitSHA:        sha,
	}, nil
}

func fetchRunArtifact(ctx context.Context, workflowRunID int64, noCache bool) (string, error) {
	key := fmt.Sprintf("run-%d", workflowRunID)

	var artifactID int64

	if !noCache && ghCache.Has(key) {
		artifactID, _ = strconv.ParseInt(ghCache.Get(key).Value(), 10, 64)
	} else {
		artifacts, _, err := gh.Actions.ListWorkflowRunArtifacts(ctx, repositoryOwner, repositoryName, workflowRunID, nil)
		if err != nil {
			return "", fmt.Errorf("list workflow run artifacts: %w", err)
		}

		if len(artifacts.Artifacts) == 0 {
			return "", PreviewError("no artifacts found")
		}

		found := false

		for _, artifact := range artifacts.Artifacts {
			if strings.HasPrefix(*artifact.Name, artifactNamePrefix) {
				artifactID = *artifact.ID
				found = true
				break
			}
		}

		if !found {
			return "", PreviewError("no firmware artifact found")
		}

		ghCache.Set(key, fmt.Sprintf("%d", artifactID), 24*time.Hour)
	}

	downloadURL := fmt.Sprintf("https://nightly.link/%s/%s/actions/artifacts/%d.zip", repositoryOwner, repositoryName, artifactID)

	return downloadArtifactFirmware(ctx, downloadURL, noCache)
}

func downloadArtifactFirmware(ctx context.Context, url string, noCache bool) (string, error) {
	sum := md5.Sum([]byte(url))
	key := hex.EncodeToString(sum[:])

	cachePath := filepath.Join(firmwareCachePath, key)

	if !noCache {
		s, err := os.Stat(cachePath)
		if err == nil && s.Size() > 0 {
			return cachePath, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read artifact: %w", err)
	}
	resp.Body.Close()

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}

	if len(zr.File) != 1 || !strings.HasSuffix(zr.File[0].Name, ".out") {
		return "", PreviewError("invalid artifact file contents")
	}

	f, err := zr.File[0].Open()
	if err != nil {
		return "", fmt.Errorf("open zip file: %w", err)
	}
	defer f.Close()

	outf, err := os.Create(cachePath)
	if err != nil {
		return "", fmt.Errorf("create cache file: %w", err)
	}

	if _, err := io.Copy(outf, f); err != nil {
		return "", fmt.Errorf("copy file: %w", err)
	}

	return cachePath, nil
}
