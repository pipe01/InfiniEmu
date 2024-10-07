package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"image"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"image/color"

	"github.com/fogleman/gg"
	"github.com/google/go-github/v66/github"
	"github.com/rs/zerolog/log"

	_ "image/png"
)

var (
	previewLock    sync.Mutex
	previewTimeout time.Duration
	previewerPath  string
)

type PreviewError string

func (e PreviewError) Error() string {
	return string(e)
}

type PreviewJob struct {
	FirmwareSpec string
	Script       string
	ShowInfo     bool
}

func main() {
	flag.StringVar(&previewerPath, "previewer", "", "Path to the previewer executable")
	flag.DurationVar(&previewTimeout, "preview-timeout", 2*time.Second, "Timeout for the previewer")
	flag.Parse()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":80"
	}

	githubToken := os.Getenv("GITHUB_TOKEN")

	gh = github.NewClient(nil).WithAuthToken(githubToken)

	if previewerPath == "" {
		panic("previewer path is required")
	}

	http.HandleFunc("GET /preview", func(w http.ResponseWriter, r *http.Request) {
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

		showInfo := r.URL.Query().Get("info") == "true"
		noCache := r.URL.Query().Get("no-cache") == "true"

		log.Info().Str("fw", fwSpecifiers[0]).Str("script", script).Msg("got request")

		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-store")

		w.WriteHeader(http.StatusOK)

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		job := PreviewJob{
			FirmwareSpec: fwSpecifiers[0],
			Script:       script,
			ShowInfo:     showInfo,
		}

		if err := previewHandler(r.Context(), w, job, noCache); err != nil {
			log.Err(err).Msg("failed to generate preview")

			var fwErr PreviewError

			if errors.As(err, &fwErr) {
				generateErrorImage(w, string(fwErr))
			} else {
				generateErrorImage(w, "failed to generate preview")
			}
		}
	})

	log.Info().Str("addr", addr).Msg("listening")

	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}

func previewHandler(ctx context.Context, rw io.Writer, job PreviewJob, noCache bool) error {
	previewLock.Lock()
	defer previewLock.Unlock()

	fwctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fwFile, err := loadFirmware(fwctx, job.FirmwareSpec, noCache)
	if err != nil {
		return fmt.Errorf("load firmware: %w", err)
	}
	cancel()

	if !noCache {
		if pr, ok := GetCachedPreview(job, fwFile.CommitSHA); ok {
			defer pr.Close()

			if _, err := io.Copy(rw, pr); err != nil {
				return fmt.Errorf("write cached preview: %w", err)
			}

			return nil
		}
	}

	prctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()

	var scrshotData bytes.Buffer

	cmd := exec.CommandContext(prctx, previewerPath, "-screenshot", "/dev/stdout", fwFile.FirmwareFilePath, "/dev/stdin")
	cmd.Stdout = &scrshotData
	cmd.Stdin = strings.NewReader(job.Script)
	cmd.Stderr = os.Stderr

	start := time.Now()

	if err := cmd.Run(); err != nil {
		if prctx.Err() != nil {
			return PreviewError("preview timed out")
		}

		return fmt.Errorf("run previewer: %w", err)
	}

	previewerRunTime := time.Since(start)

	log.Info().Str("fw", job.FirmwareSpec).Str("commit", fwFile.CommitSHA).Dur("time", previewerRunTime).Msg("preview done")

	pr, pw := io.Pipe()
	defer pw.Close()
	defer pr.Close()

	out := io.MultiWriter(rw, pw)

	go CachePreview(job, fwFile.CommitSHA, pr)

	if job.ShowInfo {
		info := fmt.Sprintf("%s %dms %s", fwFile.CommitSHA[:7], previewerRunTime.Milliseconds(), time.Now().UTC().Format(time.DateTime))

		if err := drawInfoImage(&scrshotData, out, info); err != nil {
			return fmt.Errorf("draw info image: %w", err)
		}
	} else {
		if _, err := scrshotData.WriteTo(out); err != nil {
			return fmt.Errorf("write screenshot: %w", err)
		}
	}

	return nil
}

func loadFirmware(ctx context.Context, specifier string, noCache bool) (*Artifact, error) {
	if prIDStr, ok := strings.CutPrefix(specifier, "pr/"); ok {
		prID, err := strconv.Atoi(prIDStr)
		if err != nil {
			return nil, fmt.Errorf("invalid PR ID")
		}

		return getPullRequestArtifact(ctx, prID, noCache)
	}

	if strings.HasPrefix(specifier, "heads/") || strings.HasPrefix(specifier, "tags/") {
		return getRefArtifact(ctx, specifier, noCache)
	}

	return getSHACommitArtifact(ctx, specifier, noCache)
}

func drawInfoImage(scrshotData io.Reader, out io.Writer, info string) error {
	img, _, err := image.Decode(scrshotData)
	if err != nil {
		return fmt.Errorf("decode screenshot: %w", err)
	}

	const bottomBarHeight = 20

	g := gg.NewContext(img.Bounds().Dx(), img.Bounds().Dy()+bottomBarHeight)
	g.SetColor(color.Black)
	g.Clear()

	g.DrawImage(img, 0, 0)

	g.SetColor(color.RGBA{255, 0, 255, 255})

	_, h := g.MeasureString(info)
	g.DrawString(info, 5, float64(img.Bounds().Dy())+bottomBarHeight/2+h/2)

	return g.EncodePNG(out)
}

func generateErrorImage(w io.Writer, msg string) error {
	const size = 240

	g := gg.NewContext(size, size)
	g.SetColor(color.Black)
	g.Clear()

	g.SetColor(color.RGBA{255, 0, 0, 255})
	g.DrawStringWrapped(msg, size/2, size/2, 0.5, 0.5, 200, 1, gg.AlignCenter)

	return g.EncodePNG(w)
}
