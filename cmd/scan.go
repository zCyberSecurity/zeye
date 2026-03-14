package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zCyberSecurity/zeye/internal/fingerprint"
	"github.com/zCyberSecurity/zeye/internal/masscan"
	"github.com/zCyberSecurity/zeye/internal/probe"
	"github.com/zCyberSecurity/zeye/internal/store"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run masscan and probe discovered hosts",
	Example: `  zeye scan -t 192.168.1.0/24 -p 80,443,8080 --rate 1000
  zeye scan -t targets.txt -p 1-65535 --rate 5000 --es http://localhost:9200`,
	RunE: runScan,
}

var (
	scanTargets     string
	scanPorts       string
	scanRate        int
	scanOutput      string
	scanDB          string
	scanConcurrency int
	scanTimeout     int
	scanMasscanPath string
	scanSkipProbe   bool
	scanRulesDir    string
)

func init() {
	scanCmd.Flags().StringVarP(&scanTargets, "target", "t", "", "Target: CIDR, IP, IP range, or file path (required)")
	scanCmd.Flags().StringVarP(&scanPorts, "ports", "p", "80,443,8080,8443,8888,3000,5000,9090", "Ports to scan")
	scanCmd.Flags().IntVar(&scanRate, "rate", 1000, "Masscan packet rate")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "scan.json", "Masscan JSON output file")
	scanCmd.Flags().StringVar(&scanDB, "es", "http://localhost:9200", "Elasticsearch address(es), comma-separated")
	scanCmd.Flags().IntVarP(&scanConcurrency, "concurrency", "c", 100, "Probe concurrency")
	scanCmd.Flags().IntVar(&scanTimeout, "timeout", 8, "Probe timeout in seconds")
	scanCmd.Flags().StringVar(&scanMasscanPath, "masscan", "masscan", "Path to masscan binary")
	scanCmd.Flags().BoolVar(&scanSkipProbe, "skip-probe", false, "Skip probing, only run masscan")
	scanCmd.Flags().StringVar(&scanRulesDir, "rules", "", "Fingerprint rules directory (default: embedded rules)")
	scanCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.Open(scanDB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	fpEngine, err := fingerprint.NewEngine(scanRulesDir)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}
	fmt.Printf("[*] Loaded %d fingerprint rules\n", fpEngine.RuleCount())

	runner := masscan.NewRunner(scanMasscanPath)
	target := masscan.ScanTarget{
		Hosts:      scanTargets,
		Ports:      scanPorts,
		Rate:       scanRate,
		OutputFile: scanOutput,
	}

	fmt.Printf("[*] Starting masscan: target=%s ports=%s rate=%d\n", scanTargets, scanPorts, scanRate)
	scanResults, err := runner.Run(ctx, target)
	if err != nil {
		return fmt.Errorf("masscan: %w", err)
	}

	if scanSkipProbe {
		count := 0
		for range scanResults {
			count++
		}
		fmt.Printf("[+] Scan complete: %d open ports found\n", count)
		return nil
	}

	probeEngine := probe.NewEngine(
		probe.WithConcurrency(scanConcurrency),
		probe.WithTimeoutSeconds(scanTimeout),
	)

	probeResults := probeEngine.Run(ctx, scanResults)

	saved := 0
	errors := 0
	for result := range probeResults {
		fps := fpEngine.Identify(result)
		asset := store.AssetFromProbeResult(result, fps)
		if err := db.Upsert(ctx, asset); err != nil {
			errors++
			fmt.Fprintf(os.Stderr, "[-] store error %s:%d: %v\n", result.IP, result.Port, err)
			continue
		}
		saved++
		service := result.AppProto
		if result.Title != "" {
			fmt.Printf("[+] %s:%d [%s] %d \"%s\"\n", result.IP, result.Port, service, result.StatusCode, result.Title)
		} else {
			fmt.Printf("[+] %s:%d [%s] %s\n", result.IP, result.Port, service, result.Banner)
		}
	}

	fmt.Printf("\n[*] Done: %d assets saved, %d errors\n", saved, errors)
	return nil
}

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Probe hosts from a masscan JSON file",
	Example: `  zeye probe --input scan.json
  zeye probe --input scan.json --db zeye.db --concurrency 200`,
	RunE: runProbe,
}

var (
	probeInput       string
	probeDB          string
	probeConcurrency int
	probeTimeout     int
	probeRulesDir    string
)

func init() {
	probeCmd.Flags().StringVarP(&probeInput, "input", "i", "scan.json", "Masscan JSON input file")
	probeCmd.Flags().StringVar(&probeDB, "db", "zeye.db", "SQLite database path")
	probeCmd.Flags().IntVarP(&probeConcurrency, "concurrency", "c", 100, "Probe concurrency")
	probeCmd.Flags().IntVar(&probeTimeout, "timeout", 8, "Probe timeout in seconds")
	probeCmd.Flags().StringVar(&probeRulesDir, "rules", "", "Fingerprint rules directory")
}

func runProbe(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.Open(probeDB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	fpEngine, err := fingerprint.NewEngine(probeRulesDir)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}

	scanResults, err := masscan.ParseFile(probeInput)
	if err != nil {
		return fmt.Errorf("parse input: %w", err)
	}
	fmt.Printf("[*] Loaded results from %s\n", probeInput)

	probeEngine := probe.NewEngine(
		probe.WithConcurrency(probeConcurrency),
		probe.WithTimeoutSeconds(probeTimeout),
	)

	probeResults := probeEngine.Run(ctx, scanResults)

	saved := 0
	for result := range probeResults {
		fps := fpEngine.Identify(result)
		asset := store.AssetFromProbeResult(result, fps)
		if err := db.Upsert(ctx, asset); err != nil {
			fmt.Fprintf(os.Stderr, "[-] store error %s:%d: %v\n", result.IP, result.Port, err)
			continue
		}
		saved++
		if result.Title != "" {
			fmt.Printf("[+] %s:%d [%s] %d \"%s\"\n", result.IP, result.Port, result.AppProto, result.StatusCode, result.Title)
		} else {
			fmt.Printf("[+] %s:%d [%s] %s\n", result.IP, result.Port, result.AppProto, result.Banner)
		}
	}

	fmt.Printf("\n[*] Done: %d assets saved\n", saved)
	return nil
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import masscan JSON without probing",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: zeye import <scan.json>")
		}
		db, err := store.Open(scanDB)
		if err != nil {
			return err
		}
		defer db.Close()

		results, err := masscan.ParseFile(args[0])
		if err != nil {
			return err
		}
		count := 0
		ctx := context.Background()
		for r := range results {
			asset := &store.Asset{
				IP:      r.IP,
				Port:    r.Port,
				Proto:   r.Proto,
				AppProto: r.Proto,
			}
			if err := db.Upsert(ctx, asset); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				continue
			}
			count++
		}
		fmt.Printf("[+] Imported %d records\n", count)
		return nil
	},
}
