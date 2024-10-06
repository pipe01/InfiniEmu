package main

import (
	"bytes"
	"context"
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

func main() {
	flag.StringVar(&previewerPath, "previewer", "", "Path to the previewer executable")
	flag.DurationVar(&previewTimeout, "preview-timeout", 20*time.Second, "Timeout for the previewer")
	addr := flag.String("addr", ":80", "Address to listen on")
	githubToken := flag.String("github-token", "", "GitHub token")
	flag.Parse()

	gh = github.NewClient(nil).WithAuthToken(*githubToken)

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

		showInfo := r.URL.Query().Get("info") == "true"

		log.Info().Str("fw", fwSpecifiers[0]).Str("script", script).Msg("got request")

		w.Header().Set("Content-Type", "image/png")

		if err := previewHandler(r.Context(), w, fwSpecifiers[0], script, showInfo); err != nil {
			log.Err(err).Msg("failed to generate preview")

			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Info().Str("addr", *addr).Msg("listening")

	if err := http.ListenAndServe(*addr, nil); err != nil {
		panic(err)
	}
}

func previewHandler(ctx context.Context, rw io.Writer, fwSpecifier string, script string, showInfo bool) error {
	previewLock.Lock()
	defer previewLock.Unlock()

	fwctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fwFile, err := loadFirmware(fwctx, fwSpecifier)
	if err != nil {
		return fmt.Errorf("load firmware: %w", err)
	}
	cancel()
	defer os.Remove(fwFile.FirmwareFile.Name())

	prctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()

	var scrshotData bytes.Buffer

	cmd := exec.CommandContext(prctx, previewerPath, "-screenshot", "/dev/stdout", fwFile.FirmwareFile.Name(), "/dev/stdin")
	cmd.Stdout = &scrshotData
	cmd.Stdin = strings.NewReader(script)
	cmd.Stderr = os.Stderr

	start := time.Now()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run previewer: %w", err)
	}

	previewerRunTime := time.Since(start)

	log.Info().Str("fw", fwSpecifier).Str("commit", fwFile.CommitSHA).Dur("time", previewerRunTime).Msg("preview done")

	if showInfo {
		info := fmt.Sprintf("%s %dms %s", fwFile.CommitSHA[:7], previewerRunTime.Milliseconds(), time.Now().UTC().Format(time.DateTime))

		if err := drawInfoImage(&scrshotData, rw, info); err != nil {
			return fmt.Errorf("draw info image: %w", err)
		}
	} else {
		if _, err := scrshotData.WriteTo(rw); err != nil {
			return fmt.Errorf("write screenshot: %w", err)
		}
	}

	return nil
}

func loadFirmware(ctx context.Context, specifier string) (*Artifact, error) {
	if prIDStr, ok := strings.CutPrefix(specifier, "pr/"); ok {
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