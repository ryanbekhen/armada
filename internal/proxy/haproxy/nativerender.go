package haproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// rendered is everything a configuration writes: haproxy.cfg (nil when a
// value is not a single token), its route maps by file name, and the local
// map.
type rendered struct {
	config []byte
	routes map[string][]byte
	local  []byte
}

// renderGo renders cfg with the Go renderer, the reference.
func renderGo(cfg proxy.Config, layout Layout, opts renderOptions) rendered {
	r := rendered{config: render(cfg, layout, opts)}
	if r.config != nil {
		r.routes = routeFiles(cfg, opts)
		r.local = localMap(cfg, layout, opts.node())
	}
	return r
}

// renderFellBack is called when armada-node could not render and Go did
// (tests replace it).
var renderFellBack = func(error) {}

const (
	// renderTimeout bounds one armada-node proxy render.
	renderTimeout = 30 * time.Second
	// maxRenderOutput bounds what it may write: a configuration of the
	// largest cluster proxy.Config.Validate allows is far smaller.
	maxRenderOutput = 1 << 30
)

// renderWith renders cfg with armada-node (ADR 0054) when bin is set, else,
// or when it fails, with Go; the error says why armada-node failed.
func renderWith(ctx context.Context, bin string, cfg proxy.Config, layout Layout, opts renderOptions) (rendered, error) {
	if bin == "" {
		return renderGo(cfg, layout, opts), nil
	}
	r, err := renderNative(ctx, bin, cfg, layout, opts)
	if err != nil {
		renderFellBack(err)
		return renderGo(cfg, layout, opts), err
	}
	return r, nil
}

// renderRequest is what armada-node proxy render reads.
type renderRequest struct {
	Config  proxy.Config
	Layout  Layout
	Options renderOptions
}

func renderNative(ctx context.Context, bin string, cfg proxy.Config, layout Layout, opts renderOptions) (rendered, error) {
	// Certificates by name: the keys stay in this process.
	certs := make([]proxy.Certificate, len(cfg.Certificates))
	for i, c := range cfg.Certificates {
		certs[i] = proxy.Certificate{Name: c.Name}
	}
	cfg.Certificates = certs
	in, err := json.Marshal(renderRequest{Config: cfg, Layout: layout, Options: opts})
	if err != nil {
		return rendered{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, renderTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "proxy", "render") //nolint:gosec // the runtime pack's armada-node
	cmd.Stdin = strings.NewReader(string(in))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return rendered{}, err
	}
	if err := cmd.Start(); err != nil {
		return rendered{}, err
	}
	r, readErr := readRendered(bufio.NewReader(io.LimitReader(stdout, maxRenderOutput)))
	if readErr != nil {
		cancel()
	}
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return rendered{}, fmt.Errorf("armada-node proxy render: %w: %s", err, msg)
	}
	if readErr != nil {
		return rendered{}, fmt.Errorf("armada-node proxy render: %w", readErr)
	}
	return r, nil
}

// readRendered reads `file NAME LENGTH` and the bytes for each file, or
// `unsafe`, then `end`.
func readRendered(br *bufio.Reader) (rendered, error) {
	r := rendered{routes: map[string][]byte{}}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return rendered{}, err
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 1 && f[0] == "end":
			if r.config == nil {
				r.routes = nil
			}
			return r, nil
		case len(f) == 1 && f[0] == "unsafe":
			r = rendered{}
		case len(f) == 3 && f[0] == "file":
			n, err := strconv.Atoi(f[2])
			if err != nil || n < 0 || n > maxRenderOutput {
				return rendered{}, fmt.Errorf("bad line %.60q", line)
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(br, b); err != nil {
				return rendered{}, err
			}
			switch name := f[1]; {
			case name == configFile:
				r.config = b
			case name == localFile:
				r.local = b
			case strings.HasPrefix(name, routeFilePrefix) && safeToken(name) && !strings.ContainsAny(name, "/\\"):
				r.routes[name] = b
			default:
				return rendered{}, fmt.Errorf("unexpected file %.60q", name)
			}
		default:
			return rendered{}, errors.New("bad line " + strconv.Quote(line))
		}
	}
}
