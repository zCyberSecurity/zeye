package store

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/zCyberSecurity/zeye/internal/fingerprint"
	"github.com/zCyberSecurity/zeye/internal/probe"
)

const indexName = "zeye-assets"

// DB wraps the Elasticsearch client.
type DB struct {
	es *elasticsearch.Client
}

// Open connects to Elasticsearch and ensures the index exists.
// addr can be a single address or comma-separated list: "http://host1:9200,http://host2:9200"
func Open(addr string) (*DB, error) {
	cfg := elasticsearch.Config{
		Addresses: strings.Split(addr, ","),
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create es client: %w", err)
	}
	db := &DB{es: es}
	return db, db.ensureIndex(context.Background())
}

func (d *DB) Close() error { return nil }

// docID returns a stable document ID for the (ip, port, proto) triple.
func docID(ip string, port uint16, proto string) string {
	h := md5.Sum([]byte(fmt.Sprintf("%s:%d:%s", ip, port, proto)))
	return fmt.Sprintf("%x", h)
}

func (d *DB) ensureIndex(ctx context.Context) error {
	res, err := (&esapi.IndicesExistsRequest{
		Index: []string{indexName},
	}).Do(ctx, d.es)
	if err != nil {
		return fmt.Errorf("check index: %w", err)
	}
	res.Body.Close()
	if res.StatusCode == 200 {
		return nil
	}

	res, err = (&esapi.IndicesCreateRequest{
		Index: indexName,
		Body:  strings.NewReader(indexMapping),
	}).Do(ctx, d.es)
	if err != nil {
		return fmt.Errorf("create index: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create index failed: %s", b)
	}
	return nil
}

// Upsert indexes or updates an asset. Uses scripted upsert to preserve existing
// data and increment scan_count on re-discovery.
func (d *DB) Upsert(ctx context.Context, a *Asset) error {
	now := time.Now().UTC()
	a.LastSeen = &now
	if a.FirstSeen == nil {
		a.FirstSeen = &now
	}

	params := map[string]interface{}{
		"last_seen":    a.LastSeen.Format(time.RFC3339),
		"app_proto":    a.AppProto,
		"title":        a.Title,
		"status_code":  a.StatusCode,
		"server":       a.Server,
		"body":         a.Body,
		"banner":       a.Banner,
		"tls_subject":  a.TLSSubject,
		"tls_issuer":   a.TLSIssuer,
		"tls_alt_names": nullableSlice(a.TLSAltNames),
		"fingerprints": nullableSlice(a.Fingerprints),
		"categories":  nullableSlice(a.Categories),
		"tags":         nullableSlice(a.Tags),
		"domain":      a.Domain,
		"country":     a.Country,
		"region":      a.Region,
		"city":        a.City,
	}

	body := map[string]interface{}{
		"script": map[string]interface{}{
			"lang": "painless",
			"source": `
				ctx._source.last_seen = params.last_seen;
				ctx._source.scan_count = ctx._source.containsKey('scan_count') ? ctx._source.scan_count + 1 : 1;
				if (params.app_proto   != '') ctx._source.app_proto   = params.app_proto;
				if (params.title       != '') ctx._source.title       = params.title;
				if (params.status_code != 0)  ctx._source.status_code = params.status_code;
				if (params.server      != '') ctx._source.server      = params.server;
				if (params.body        != '') ctx._source.body        = params.body;
				if (params.banner      != '') ctx._source.banner      = params.banner;
				if (params.tls_subject != '') ctx._source.tls_subject = params.tls_subject;
				if (params.tls_issuer  != '') ctx._source.tls_issuer  = params.tls_issuer;
				if (params.tls_alt_names != null && params.tls_alt_names.length > 0) ctx._source.tls_alt_names = params.tls_alt_names;
				if (params.fingerprints != null && params.fingerprints.length > 0)   ctx._source.fingerprints  = params.fingerprints;
				if (params.categories  != null && params.categories.length > 0)      ctx._source.categories    = params.categories;
				if (params.tags        != null && params.tags.length > 0)            ctx._source.tags          = params.tags;
				if (params.domain      != '') ctx._source.domain  = params.domain;
				if (params.country     != '') ctx._source.country = params.country;
				if (params.region      != '') ctx._source.region  = params.region;
				if (params.city        != '') ctx._source.city    = params.city;
			`,
			"params": params,
		},
		"upsert": a,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	retries := 3
	res, err := (&esapi.UpdateRequest{
		Index:           indexName,
		DocumentID:      docID(a.IP, a.Port, a.Proto),
		Body:            bytes.NewReader(data),
		RetryOnConflict: &retries,
	}).Do(ctx, d.es)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.IsError() {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("upsert failed: %s", b)
	}
	return nil
}

// Query searches assets using an Elasticsearch Query DSL map.
func (d *DB) Query(ctx context.Context, dsl map[string]interface{}, opts QueryOpts) ([]*Asset, error) {
	size := opts.Limit
	if size <= 0 {
		size = 50
	}

	searchBody := map[string]interface{}{
		"query": dsl,
		"sort":  parseSort(opts.OrderBy),
	}
	data, err := json.Marshal(searchBody)
	if err != nil {
		return nil, err
	}

	res, err := (&esapi.SearchRequest{
		Index: []string{indexName},
		Body:  bytes.NewReader(data),
		Size:  intPtr(size),
		From:  intPtr(opts.Offset),
	}).Do(ctx, d.es)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.IsError() {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("search failed: %s", b)
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source *Asset `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	assets := make([]*Asset, 0, len(result.Hits.Hits))
	for _, h := range result.Hits.Hits {
		assets = append(assets, h.Source)
	}
	return assets, nil
}

// Count returns the number of documents matching the DSL query.
func (d *DB) Count(ctx context.Context, dsl map[string]interface{}) (int64, error) {
	data, err := json.Marshal(map[string]interface{}{"query": dsl})
	if err != nil {
		return 0, err
	}

	res, err := (&esapi.CountRequest{
		Index: []string{indexName},
		Body:  bytes.NewReader(data),
	}).Do(ctx, d.es)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.IsError() {
		b, _ := io.ReadAll(res.Body)
		return 0, fmt.Errorf("count failed: %s", b)
	}

	var result struct {
		Count int64 `json:"count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result.Count, nil
}

// AssetFromProbeResult converts a probe result + fingerprint matches to an Asset.
func AssetFromProbeResult(r *probe.ProbeResult, fps []fingerprint.MatchResult) *Asset {
	var fpNames []string
	versions := map[string]string{}
	catSet := map[string]bool{}
	tagSet := map[string]bool{}
	for _, fp := range fps {
		fpNames = append(fpNames, fp.Name)
		if fp.Version != "" {
			versions[fp.Name] = fp.Version
		}
		if fp.Category != "" {
			catSet[fp.Category] = true
		}
		for _, t := range fp.Tags {
			tagSet[t] = true
		}
	}
	var categories []string
	for c := range catSet {
		categories = append(categories, c)
	}
	var tags []string
	for t := range tagSet {
		tags = append(tags, t)
	}

	body := r.Body
	if len(body) > 65536 {
		body = body[:65536]
	}

	tlsExpiry := ""
	if !r.TLSExpiry.IsZero() {
		tlsExpiry = r.TLSExpiry.Format(time.RFC3339)
	}

	return &Asset{
		IP:           r.IP,
		Port:         r.Port,
		Proto:        r.Proto,
		AppProto:     r.AppProto,
		Title:        r.Title,
		StatusCode:   r.StatusCode,
		Server:       r.Server,
		Body:         body,
		Headers:      r.Headers,
		Banner:       r.Banner,
		TLSSubject:   r.TLSSubject,
		TLSIssuer:    r.TLSIssuer,
		TLSAltNames:  r.TLSAltNames,
		TLSExpiry:    tlsExpiry,
		Fingerprints: fpNames,
		Versions:     versions,
		Categories:   categories,
		Tags:         tags,
		Domain:       extractDomain(r.TLSAltNames),
	}
}

func parseSort(orderBy string) []map[string]interface{} {
	if orderBy == "" {
		return []map[string]interface{}{{"last_seen": "desc"}}
	}
	parts := strings.Fields(orderBy)
	field := strings.ToLower(parts[0])
	dir := "desc"
	if len(parts) > 1 && strings.EqualFold(parts[1], "ASC") {
		dir = "asc"
	}
	return []map[string]interface{}{{field: dir}}
}

func intPtr(i int) *int { return &i }

func nullableSlice(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

// extractDomain returns the first domain name from TLS SAN entries.
func extractDomain(altNames []string) string {
	for _, name := range altNames {
		if strings.HasPrefix(name, "*.") {
			return name[2:]
		}
		if net.ParseIP(name) == nil && name != "" {
			return name
		}
	}
	return ""
}
