package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "zeye",
	Short: "zeye - Network asset mapping platform",
	Long: `zeye is a local network asset mapping and search platform.

Import scan results from masscan, nmap, or zmap, and probe discovered ports
for application-layer details, then search your asset inventory with
FOFA-style syntax.

Usage:
  zeye probe  --input scan.json                      # probe & store results
  zeye import scan.json                              # store without probing
  zeye query  'title*="admin" && port=80'            # search assets
`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(probeCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(queryCmd)
}
