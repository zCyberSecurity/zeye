package masscan

// ScanTarget describes a masscan scan task.
type ScanTarget struct {
	Hosts      string // CIDR, IP, IP range, or file path
	Ports      string // e.g. "80,443,8080-9090"
	Rate       int    // masscan --rate
	OutputFile string // path for JSON output
}

// ScanResult represents a single open port found by masscan.
type ScanResult struct {
	IP    string
	Port  uint16
	Proto string // tcp / udp
}

// masscanRecord mirrors masscan's JSON output structure.
type masscanRecord struct {
	IP        string          `json:"ip"`
	Timestamp string          `json:"timestamp"`
	Ports     []masscanPort   `json:"ports"`
}

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}
