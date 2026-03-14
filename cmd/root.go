package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "zeye",
	Short: "zeye - Network asset mapping platform",
	Long: `zeye is a network asset mapping and search platform similar to FOFA.

Usage:
  zeye scan   -t 192.168.1.0/24 -p 80,443,8080 --rate 1000
  zeye probe  --input scan.json
  zeye query  'title*="admin" && port=80'
`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(probeCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(importCmd)
}
