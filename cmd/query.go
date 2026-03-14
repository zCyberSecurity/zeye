package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/zCyberSecurity/zeye/internal/query"
	"github.com/zCyberSecurity/zeye/internal/store"
)

var queryCmd = &cobra.Command{
	Use:   "query [expression]",
	Short: "Query assets using FOFA-like syntax",
	Long: `Query assets using FOFA-like syntax.

Supported fields:
  ip, port, proto, app_proto, title, server, body, banner
  tls_subject, tls_issuer, tls_alt_names, status_code
  fingerprint, tag, first_seen, last_seen

Operators:
  =    exact match      title="Login Page"
  !=   not equal        server!="Apache"
  *=   contains         title*="admin"
  ^=   starts with      ip^="192.168"
  $=   ends with        ip$=".1"
  ~=   regex match      title~="[Ll]ogin"
  >    greater than     port>1000
  >=   greater equal    status_code>=200
  <    less than        port<1024
  <=   less equal       status_code<=299

Logical:
  &&   AND
  ||   OR
  !    NOT
  ()   Grouping

Examples:
  zeye query 'port=80'
  zeye query 'title*="admin" && app_proto="http"'
  zeye query 'ip="192.168.1.0/24" && port=80'
  zeye query '(fingerprint="WordPress" || fingerprint="Drupal") && port=80'
  zeye query 'tls_subject*="google.com"'
`,
	Args: cobra.ExactArgs(1),
	RunE: runQuery,
}

var (
	queryDB     string
	queryLimit  int
	queryOffset int
	queryFormat string
	queryFields string
)

func init() {
	queryCmd.Flags().StringVar(&queryDB, "es", "http://localhost:9200", "Elasticsearch address(es), comma-separated")
	queryCmd.Flags().IntVarP(&queryLimit, "limit", "l", 50, "Max results to return")
	queryCmd.Flags().IntVar(&queryOffset, "offset", 0, "Result offset")
	queryCmd.Flags().StringVarP(&queryFormat, "format", "f", "table", "Output format: table, json, csv")
	queryCmd.Flags().StringVar(&queryFields, "fields", "ip,port,app_proto,title,server,fingerprints", "Fields to display (comma separated)")
}

func runQuery(cmd *cobra.Command, args []string) error {
	expr := args[0]

	ast, err := query.Parse(expr)
	if err != nil {
		return fmt.Errorf("parse query: %w", err)
	}

	translated, err := query.Translate(ast)
	if err != nil {
		return fmt.Errorf("translate query: %w", err)
	}

	db, err := store.Open(queryDB)
	if err != nil {
		return fmt.Errorf("open es: %w", err)
	}
	defer db.Close()

	opts := store.QueryOpts{
		Limit:   queryLimit,
		Offset:  queryOffset,
		OrderBy: "last_seen DESC",
	}

	assets, err := db.Query(context.Background(), translated.DSL, opts)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	total, err := db.Count(context.Background(), translated.DSL)
	if err != nil {
		return fmt.Errorf("count: %w", err)
	}

	fields := strings.Split(queryFields, ",")

	switch queryFormat {
	case "json":
		return outputJSON(assets)
	case "csv":
		return outputCSV(assets, fields)
	default:
		return outputTable(assets, fields, total)
	}
}

func outputTable(assets []*store.Asset, fields []string, total int64) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(fields, "\t"))
	fmt.Fprintln(w, strings.Repeat("-", 80))
	for _, a := range assets {
		row := make([]string, len(fields))
		for i, f := range fields {
			row[i] = assetField(a, strings.TrimSpace(f))
		}
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
	fmt.Printf("\nTotal: %d results (showing %d)\n", total, len(assets))
	return nil
}

func outputJSON(assets []*store.Asset) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(assets)
}

func outputCSV(assets []*store.Asset, fields []string) error {
	fmt.Println(strings.Join(fields, ","))
	for _, a := range assets {
		row := make([]string, len(fields))
		for i, f := range fields {
			v := assetField(a, strings.TrimSpace(f))
			if strings.ContainsAny(v, ",\"\n") {
				v = `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
			}
			row[i] = v
		}
		fmt.Println(strings.Join(row, ","))
	}
	return nil
}

func assetField(a *store.Asset, field string) string {
	switch field {
	case "ip":
		return a.IP
	case "port":
		return fmt.Sprintf("%d", a.Port)
	case "proto":
		return a.Proto
	case "app_proto":
		return a.AppProto
	case "title":
		return a.Title
	case "server":
		return a.Server
	case "status_code":
		if a.StatusCode == 0 {
			return "-"
		}
		return fmt.Sprintf("%d", a.StatusCode)
	case "fingerprints":
		return strings.Join(a.Fingerprints, ", ")
	case "tags":
		return strings.Join(a.Tags, ", ")
	case "tls_subject":
		return a.TLSSubject
	case "last_seen":
		return a.LastSeen.Format("2006-01-02 15:04:05")
	case "first_seen":
		return a.FirstSeen.Format("2006-01-02 15:04:05")
	default:
		return ""
	}
}
