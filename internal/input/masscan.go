package input

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

type masscanRecord struct {
	IP    string        `json:"ip"`
	Ports []masscanPort `json:"ports"`
}

type masscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

// parseMasscan reads masscan JSON output (NDJSON or array format) from r.
func parseMasscan(r io.Reader, out chan<- ScanResult) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4<<20), 4<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line == "[" || line == "]" {
			continue
		}
		line = strings.Trim(line, ",")
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var rec masscanRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		for _, p := range rec.Ports {
			if strings.ToLower(p.Status) != "open" {
				continue
			}
			out <- ScanResult{
				IP:    rec.IP,
				Port:  uint16(p.Port),
				Proto: normalizeProto(p.Proto),
			}
		}
	}
}
