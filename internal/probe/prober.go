package probe

import "context"

// Prober is the interface for application-layer protocol probers.
type Prober interface {
	// Protocol returns the identifier of the protocol this prober handles.
	Protocol() string

	// ShouldProbe returns true if this prober should attempt the given port.
	ShouldProbe(port uint16) bool

	// Probe performs the application-layer probe and returns a result.
	Probe(ctx context.Context, ip string, port uint16) (*ProbeResult, error)
}
