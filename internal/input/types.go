package input

// ScanResult represents a single open port discovered by an external scanner.
type ScanResult struct {
	IP    string
	Port  uint16
	Proto string // "tcp" | "udp"
}
