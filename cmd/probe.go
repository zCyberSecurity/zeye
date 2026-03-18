package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/zCyberSecurity/zeye/internal/fingerprint"
	"github.com/zCyberSecurity/zeye/internal/input"
	"github.com/zCyberSecurity/zeye/internal/probe"
	"github.com/zCyberSecurity/zeye/internal/store"
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe open ports from a scan result file",
	Example: `
  zeye probe --input scan.json -o results.json
  zeye probe --input nmap.xml -o results.json
  zeye probe --input zmap.csv --format zmap -o results.json`,
	RunE: runProbe,
}

var (
	probeInput       string
	probeFormat      string
	probeOutput      string
	probeConcurrency int
	probeTimeout     int
	probeRulesDir    string
)

func init() {
	probeCmd.Flags().StringVarP(&probeInput, "input", "i", "", "Scan result file (masscan JSON / nmap XML / zmap CSV) (required)")
	probeCmd.Flags().StringVarP(&probeFormat, "format", "f", "auto", "Input format: auto, masscan, nmap, zmap")
	probeCmd.Flags().StringVarP(&probeOutput, "output", "o", "probe.json", "Write probe results to a JSON file")
	probeCmd.Flags().IntVarP(&probeConcurrency, "concurrency", "c", 100, "Probe concurrency")
	probeCmd.Flags().IntVar(&probeTimeout, "timeout", 8, "Probe timeout in seconds")
	probeCmd.Flags().StringVar(&probeRulesDir, "rules", "", "Fingerprint rules directory (default: embedded rules)")
	_ = probeCmd.MarkFlagRequired("input")
}

func runProbe(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fpEngine, err := fingerprint.NewEngine(probeRulesDir)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}
	fmt.Printf("[*] Loaded %d fingerprint rules\n", fpEngine.RuleCount())

	// Drain input into a slice so we know the total for the progress bar.
	raw, err := input.ParseFile(probeInput, input.Format(probeFormat))
	if err != nil {
		return fmt.Errorf("parse input: %w", err)
	}
	fmt.Printf("[*] Loading %s ...\n", probeInput)
	var inputs []input.ScanResult
	for sr := range raw {
		inputs = append(inputs, sr)
	}
	total := len(inputs)
	fmt.Printf("[*] %d ports to probe\n", total)
	if total == 0 {
		return nil
	}

	// Feed slice into probe engine via a channel.
	feed := make(chan input.ScanResult, 256)
	go func() {
		defer close(feed)
		for _, sr := range inputs {
			select {
			case <-ctx.Done():
				return
			case feed <- sr:
			}
		}
	}()

	probeEngine := probe.NewEngine(
		probe.WithConcurrency(probeConcurrency),
		probe.WithTimeoutSeconds(probeTimeout),
	)

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionShowElapsedTimeOnFinish(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	var assets []*store.Asset
	l7Stats := make(map[string]int)
	for result := range probeEngine.Run(ctx, feed) {
		fps := fpEngine.Identify(result)
		asset := store.AssetFromProbeResult(result, fps)
		assets = append(assets, asset)
		if isL7(asset.AppProto) {
			l7Stats[asset.AppProto]++
		}
		bar.Describe(formatL7Stats(l7Stats))
		_ = bar.Add(1)
	}
	_ = bar.Finish()

	if err := writeJSON(probeOutput, assets); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	fmt.Printf("[*] Done: %d assets → %s\n", len(assets), probeOutput)
	fmt.Printf("[*] L7 breakdown: %s\n", formatL7Stats(l7Stats))
	return nil
}

// isL7 returns true when AppProto is a recognized application-layer protocol
// (i.e. something more specific than the raw transport proto).
func isL7(appProto string) bool {
	switch appProto {
	case "tcp", "udp", "sctp", "":
		return false
	default:
		return true
	}
}

// formatL7Stats renders the protocol map as "http:10 https:5 ssh:3", sorted by count desc.
func formatL7Stats(stats map[string]int) string {
	if len(stats) == 0 {
		return "L7: -"
	}
	type kv struct {
		proto string
		count int
	}
	pairs := make([]kv, 0, len(stats))
	for p, c := range stats {
		pairs = append(pairs, kv{p, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].proto < pairs[j].proto
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = fmt.Sprintf("%s:%d", p.proto, p.count)
	}
	return strings.Join(parts, " ")
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
