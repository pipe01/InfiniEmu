package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/google/go-github/v66/github"
)

const (
	repositoryOwner    = "InfiniTimeOrg"
	repositoryName     = "InfiniTime"
	workflowFileName   = "main.yml"
	artifactNamePrefix = "InfiniTime image"
)

var gh *github.Client

type Artifact struct {
	FirmwareFile *os.File
	CommitSHA    string
}

type FirmwareLoadError string

func (e FirmwareLoadError) Error() string {
	return string(e)
}

func isNotFoundError(err error) bool {
	if gerr, ok := err.(*github.ErrorResponse); ok {
		return gerr.Response.StatusCode == http.StatusNotFound
	}

	return false
}

func getPullRequestArtifact(ctx context.Context, id int) (*Artifact, error) {
	pr, _, err := gh.PullRequests.Get(ctx, repositoryOwner, repositoryName, id)
	if err != nil {
		if isNotFoundError(err) {
			return nil, FirmwareLoadError("pull request not found")
		}

		return nil, fmt.Errorf("list commits: %w", err)
	}

	return getSHACommitArtifact(ctx, *pr.Head.SHA)
}

func getRefArtifact(ctx context.Context, refName string) (*Artifact, error) {
	ref, _, err := gh.Git.GetRef(ctx, repositoryOwner, repositoryName, refName)
	if err != nil {
		if isNotFoundError(err) {
			return nil, FirmwareLoadError("ref not found")
		}

		return nil, fmt.Errorf("get ref: %w", err)
	}

	return getSHACommitArtifact(ctx, *ref.Object.SHA)
}

func getSHACommitArtifact(ctx context.Context, sha string) (*Artifact, error) {
	runs, _, err := gh.Actions.ListWorkflowRunsByFileName(ctx, repositoryOwner, repositoryName, workflowFileName, &github.ListWorkflowRunsOptions{
		HeadSHA: sha,
	})
	if err != nil {
		return nil, fmt.Errorf("list workflow runs: %w", err)
	}

	if len(runs.WorkflowRuns) == 0 {
		return nil, FirmwareLoadError(fmt.Sprintf("no workflow runs found for commit '%s'", sha))
	}

	latest := slices.MaxFunc(runs.WorkflowRuns, func(a, b *github.WorkflowRun) int {
		at := a.CreatedAt.GetTime()
		bt := b.CreatedAt.GetTime()

		if at.Before(*bt) {
			return -1
		}
		if at.After(*bt) {
			return 1
		}

		return 0
	})

	f, err := getArtifact(ctx, *latest.ID)
	if err != nil {
		return nil, err
	}

	return &Artifact{
		FirmwareFile: f,
		CommitSHA:    sha,
	}, nil
}

func getArtifact(ctx context.Context, workflowRunID int64) (*os.File, error) {
	artifacts, _, err := gh.Actions.ListWorkflowRunArtifacts(ctx, repositoryOwner, repositoryName, workflowRunID, nil)
	if err != nil {
		return nil, fmt.Errorf("list workflow run artifacts: %w", err)
	}

	if len(artifacts.Artifacts) == 0 {
		return nil, FirmwareLoadError("no artifacts found")
	}

	for _, artifact := range artifacts.Artifacts {
		if strings.HasPrefix(*artifact.Name, artifactNamePrefix) {
			downloadURL := fmt.Sprintf("https://nightly.link/%s/%s/actions/artifacts/%d.zip", repositoryOwner, repositoryName, *artifact.ID)

			return downloadArtifactFirmware(ctx, downloadURL)
		}
	}

	return nil, FirmwareLoadError("no firmware artifact found")
}

func downloadArtifactFirmware(ctx context.Context, url string) (*os.File, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download artifact: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	resp.Body.Close()

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	if len(zr.File) != 1 || !strings.HasSuffix(zr.File[0].Name, ".out") {
		return nil, FirmwareLoadError("invalid artifact file contents")
	}

	f, err := zr.File[0].Open()
	if err != nil {
		return nil, fmt.Errorf("open zip file: %w", err)
	}
	defer f.Close()

	outf, err := os.CreateTemp("/tmp", "*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer outf.Close()

	if _, err := io.Copy(outf, f); err != nil {
		return nil, fmt.Errorf("copy file: %w", err)
	}

	return outf, nil
}
