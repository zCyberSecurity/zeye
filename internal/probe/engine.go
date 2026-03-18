package probe

import (
	"context"
	"sync"
	"time"

	"github.com/zCyberSecurity/zeye/internal/input"
)

// Engine schedules and runs probers concurrently.
type Engine struct {
	// portIndex maps a port number to the specific probers that handle it.
	// Probers that declare no specific ports (HTTP, TCP) are stored in fallbacks.
	portIndex map[uint16][]Prober
	fallbacks []Prober

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

// NewEngine creates an Engine with default probers.
func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		concurrency: 100,
		timeout:     8 * time.Second,
		portIndex:   make(map[uint16][]Prober),
	}
	for _, o := range opts {
		o(e)
	}

	specific := []Prober{
		// Text banner protocols
		NewSSHProber(e.timeout),
		NewTelnetProber(e.timeout),
		NewFTPProber(e.timeout),
		NewSMTPProber(e.timeout),
		NewIMAPProber(e.timeout),
		NewPOP3Prober(e.timeout),
		// Databases
		NewMySQLProber(e.timeout),
		NewPostgreSQLProber(e.timeout),
		NewMongoDBProber(e.timeout),
		NewRedisProber(e.timeout),
		NewMemcachedProber(e.timeout),
		NewOracleProber(e.timeout),
		// Binary / industrial protocols
		NewSMBProber(e.timeout),
		NewSOCKS5Prober(e.timeout),
		NewMQTTProber(e.timeout),
		NewModbusProber(e.timeout),
		NewDNP3Prober(e.timeout),
		NewNTPProber(e.timeout),
	}
	e.fallbacks = []Prober{
		NewHTTPProber(e.timeout),
		NewTCPProber(e.timeout),
	}

	// Build port → probers index by probing all 65535 ports with ShouldProbe.
	for _, p := range specific {
		for port := uint16(1); port < 65535; port++ {
			if p.ShouldProbe(port) {
				e.portIndex[port] = append(e.portIndex[port], p)
			}
		}
	}
	return e
}

// Register adds a custom prober. It is indexed the same way as built-in probers.
func (e *Engine) Register(p Prober) {
	for port := uint16(1); port < 65535; port++ {
		if p.ShouldProbe(port) {
			// Prepend so custom probers run before built-ins for their ports.
			e.portIndex[port] = append([]Prober{p}, e.portIndex[port]...)
		}
	}
}

// Run consumes scan results and returns probe results via a channel.
func (e *Engine) Run(ctx context.Context, in <-chan input.ScanResult) <-chan *ProbeResult {
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
			go func(sr input.ScanResult) {
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

func (e *Engine) probeOne(ctx context.Context, sr input.ScanResult) *ProbeResult {
	pCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// 1. Try specific probers for this port first (O(1) lookup).
	for _, p := range e.portIndex[sr.Port] {
		result, err := p.Probe(pCtx, sr.IP, sr.Port)
		if err == nil && result != nil {
			result.Proto = sr.Proto
			return result
		}
	}

	// 2. Fall back to HTTP then TCP banner grab.
	for _, p := range e.fallbacks {
		result, err := p.Probe(pCtx, sr.IP, sr.Port)
		if err == nil && result != nil {
			result.Proto = sr.Proto
			return result
		}
	}

	// 3. Record the port even if all probes failed.
	return &ProbeResult{
		IP:        sr.IP,
		Port:      sr.Port,
		Proto:     sr.Proto,
		AppProto:  sr.Proto,
		Timestamp: time.Now(),
	}
}
