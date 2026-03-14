package masscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner wraps the masscan binary.
type Runner struct {
	binaryPath string
}

func NewRunner(binaryPath string) *Runner {
	return &Runner{binaryPath: binaryPath}
}

// Run executes masscan and streams results as they are written to the output file.
func (r *Runner) Run(ctx context.Context, target ScanTarget) (<-chan ScanResult, error) {
	if target.OutputFile == "" {
		target.OutputFile = filepath.Join(os.TempDir(), fmt.Sprintf("zeye_%d.json", time.Now().Unix()))
	}

	args := []string{
		target.Hosts,
		"-p", target.Ports,
		"--rate", fmt.Sprintf("%d", target.Rate),
		"-oJ", target.OutputFile,
		"--open",
	}

	cmd := exec.CommandContext(ctx, r.binaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start masscan: %w", err)
	}

	out := make(chan ScanResult, 256)

	go func() {
		defer close(out)
		defer cmd.Wait()

		// Poll the output file while masscan runs.
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
				// masscan finished; do a final parse.
				streamFile(ctx, target.OutputFile, out)
				return
			}

			time.Sleep(500 * time.Millisecond)

			streamFile(ctx, target.OutputFile, out)
		}
	}()

	// Better approach: wait for masscan to exit then parse the full file.
	outFinal := make(chan ScanResult, 256)
	go func() {
		defer close(outFinal)
		if err := cmd.Wait(); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "[!] masscan exited: %v\n", err)
			}
		}
		f, err := ParseFile(target.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] parse masscan output: %v\n", err)
			return
		}
		for r := range f {
			select {
			case <-ctx.Done():
				return
			case outFinal <- r:
			}
		}
	}()

	// Close the polling goroutine channel (it's unused now)
	go func() {
		for range out {
		}
	}()

	return outFinal, nil
}

// streamFile parses whatever has been written to the file so far.
func streamFile(ctx context.Context, path string, out chan<- ScanResult) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line == "[" || line == "]" {
			continue
		}
		line = strings.TrimPrefix(line, ",")
		line = strings.TrimSuffix(line, ",")

		var record masscanRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		for _, p := range record.Ports {
			if p.Status != "open" {
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
}
