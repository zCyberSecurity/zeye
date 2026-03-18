package input

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parseZmap reads zmap CSV output from r.
//
// zmap should be invoked with --output-fields to include IP and port columns.
// Recognised column names:
//   - IP:   saddr, ip, src_addr
//   - Port: dport, port, dst_port
//
// Proto is always "tcp" (zmap only performs TCP scanning).
//
// Example invocation:
//
//	zmap -p 80 10.0.0.0/8 --output-fields="saddr,dport" -o results.csv
func parseZmap(r io.Reader, out chan<- ScanResult) error {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true

	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("read zmap CSV header: %w", err)
	}

	ipCol, portCol := -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "saddr", "ip", "src_addr":
			ipCol = i
		case "dport", "port", "dst_port":
			portCol = i
		}
	}
	if ipCol == -1 {
		return fmt.Errorf("zmap CSV: no IP column (expected saddr, ip, or src_addr)")
	}
	if portCol == -1 {
		return fmt.Errorf("zmap CSV: no port column (expected dport, port, or dst_port); " +
			"run zmap with --output-fields=\"saddr,dport\"")
	}

	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(row) <= ipCol || len(row) <= portCol {
			continue
		}

		ip := strings.TrimSpace(row[ipCol])
		port, err := strconv.ParseUint(strings.TrimSpace(row[portCol]), 10, 16)
		if err != nil {
			continue
		}
		out <- ScanResult{IP: ip, Port: uint16(port), Proto: "tcp"}
	}
	return nil
}
