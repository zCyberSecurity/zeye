package probe

import (
	"context"
	"sync"
	"time"

	"github.com/zCyberSecurity/zeye/internal/masscan"
)

// Engine schedules and runs probers concurrently.
type Engine struct {
	probers     []Prober
	concurrency int
	timeout     time.Duration
}

type Option func(*Engine)

func WithConcurrency(n int) Option {
	return func(e *Engine) { e.concurrency = n }
}

func WithTimeoutSeconds(s int) Option {
	return func(e *Engine) { e.timeout = time.Duration(s) * time.Second }
}

// NewEngine creates an Engine with default probers (HTTP, TCP banner).
func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		concurrency: 100,
		timeout:     8 * time.Second,
	}
	for _, o := range opts {
		o(e)
	}
	// Register default probers (order matters: HTTP first)
	e.probers = []Prober{
		NewHTTPProber(e.timeout),
		NewTCPProber(e.timeout),
	}
	return e
}

// Register adds a custom prober to the engine.
func (e *Engine) Register(p Prober) {
	e.probers = append([]Prober{p}, e.probers...)
}

// Run consumes scan results and returns probe results via a channel.
func (e *Engine) Run(ctx context.Context, in <-chan masscan.ScanResult) <-chan *ProbeResult {
	out := make(chan *ProbeResult, e.concurrency)

	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	go func() {
		defer func() {
			wg.Wait()
			close(out)
		}()

		for sr := range in {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}

			wg.Add(1)
			go func(sr masscan.ScanResult) {
				defer wg.Done()
				defer func() { <-sem }()

				result := e.probeOne(ctx, sr)
				if result == nil {
					return
				}
				select {
				case <-ctx.Done():
				case out <- result:
				}
			}(sr)
		}
	}()

	return out
}

func (e *Engine) probeOne(ctx context.Context, sr masscan.ScanResult) *ProbeResult {
	pCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Try probers in order; return the first successful result.
	for _, p := range e.probers {
		if !p.ShouldProbe(sr.Port) {
			continue
		}
		result, err := p.Probe(pCtx, sr.IP, sr.Port)
		if err == nil && result != nil {
			result.Proto = sr.Proto
			return result
		}
	}

	// Fallback: return a minimal result so the port is recorded.
	return &ProbeResult{
		IP:        sr.IP,
		Port:      sr.Port,
		Proto:     sr.Proto,
		AppProto:  sr.Proto,
		Timestamp: time.Now(),
	}
}
