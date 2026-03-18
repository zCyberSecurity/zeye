package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/zCyberSecurity/zeye/internal/input"
	"github.com/zCyberSecurity/zeye/internal/store"
)

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import scan results into the database without probing",
	Example: `  zeye import scan.json
  zeye import nmap.xml
  zeye import zmap.csv --format zmap`,
	Args: cobra.ExactArgs(1),
	RunE: runImport,
}

var (
	importFormat string
	importDB     string
)

func init() {
	importCmd.Flags().StringVarP(&importFormat, "format", "f", "auto", "Input format: auto, masscan, nmap, zmap")
	importCmd.Flags().StringVar(&importDB, "es", "http://localhost:9200", "Elasticsearch address(es), comma-separated")
}

func runImport(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	db, err := store.Open(importDB)
	if err != nil {
		return err
	}
	defer db.Close()

	results, err := input.ParseFile(args[0], input.Format(importFormat))
	if err != nil {
		return err
	}

	count := 0
	for r := range results {
		asset := &store.Asset{
			IP:       r.IP,
			Port:     r.Port,
			Proto:    r.Proto,
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
}
