package masscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ParseFile reads a masscan JSON output file and streams results.
// Supports both array format and NDJSON (one JSON object per line).
func ParseFile(path string) (<-chan ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	out := make(chan ScanResult, 256)

	go func() {
		defer close(out)
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4<<20), 4<<20)

		ctx := context.Background()

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if len(line) == 0 || line == "[" || line == "]" {
				continue
			}
			// Strip leading/trailing commas (masscan array format)
			line = strings.TrimPrefix(line, ",")
			line = strings.TrimSuffix(line, ",")
			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			var record masscanRecord
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				continue
			}
			for _, p := range record.Ports {
				if strings.ToLower(p.Status) != "open" {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case out <- ScanResult{
					IP:    record.IP,
					Port:  uint16(p.Port),
					Proto: p.Proto,
				}:
				}
			}
		}
	}()

	return out, nil
}
