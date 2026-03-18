package input

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Format specifies the scanner output format.
type Format string

const (
	FormatAuto    Format = "auto"
	FormatMasscan Format = "masscan"
	FormatNmap    Format = "nmap"
	FormatZmap    Format = "zmap"
)

// ParseFile opens path, auto-detects the format (unless fmt is specified), and
// returns a channel that streams deduplicated ScanResults.
func ParseFile(path string, format Format) (<-chan ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	if format == FormatAuto {
		format, err = detectFormat(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("detect format of %s: %w", path, err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return nil, fmt.Errorf("seek %s: %w", path, err)
		}
	}

	raw := make(chan ScanResult, 256)
	go func() {
		defer close(raw)
		defer f.Close()

		switch format {
		case FormatMasscan:
			parseMasscan(f, raw)
		case FormatNmap:
			parseNmap(f, raw)
		case FormatZmap:
			if err := parseZmap(f, raw); err != nil {
				fmt.Fprintf(os.Stderr, "[!] zmap parse error: %v\n", err)
			}
		default:
			fmt.Fprintf(os.Stderr, "[!] unknown input format: %q\n", format)
		}
	}()

	return Dedup(raw), nil
}

// Dedup wraps in and drops duplicate ip:port:proto tuples.
func Dedup(in <-chan ScanResult) <-chan ScanResult {
	out := make(chan ScanResult, 256)
	go func() {
		defer close(out)
		seen := make(map[string]struct{})
		for sr := range in {
			key := sr.IP + ":" + strconv.Itoa(int(sr.Port)) + ":" + sr.Proto
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out <- sr
		}
	}()
	return out
}

// detectFormat peeks at r to infer the scanner output format.
func detectFormat(r io.Reader) (Format, error) {
	buf := make([]byte, 512)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		return FormatAuto, err
	}
	s := strings.TrimSpace(string(buf[:n]))
	switch {
	case strings.HasPrefix(s, "<?xml"), strings.HasPrefix(s, "<nmaprun"), strings.HasPrefix(s, "<!DOCTYPE"):
		return FormatNmap, nil
	case strings.HasPrefix(s, "["), strings.HasPrefix(s, "{"):
		return FormatMasscan, nil
	default:
		return FormatZmap, nil
	}
}

// normalizeProto lowercases and validates protocol strings.
func normalizeProto(s string) string {
	switch strings.ToLower(s) {
	case "tcp", "udp", "sctp":
		return strings.ToLower(s)
	default:
		return "tcp"
	}
}
