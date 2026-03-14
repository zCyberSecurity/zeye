package store

// indexMapping is the Elasticsearch index mapping for zeye-assets.
const indexMapping = `{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1
  },
  "mappings": {
    "dynamic": false,
    "properties": {
      "ip":           { "type": "ip" },
      "port":         { "type": "integer" },
      "proto":        { "type": "keyword" },
      "app_proto":    { "type": "keyword" },
      "title": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } }
      },
      "status_code":  { "type": "integer" },
      "server":       { "type": "keyword" },
      "body":         { "type": "text" },
      "headers":      { "type": "object", "enabled": false },
      "banner": {
        "type": "text",
        "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } }
      },
      "tls_subject":   { "type": "keyword" },
      "tls_issuer":    { "type": "keyword" },
      "tls_alt_names": { "type": "keyword" },
      "tls_expiry":    { "type": "date" },
      "fingerprints":  { "type": "keyword" },
      "tags":          { "type": "keyword" },
      "first_seen":    { "type": "date" },
      "last_seen":     { "type": "date" },
      "scan_count":    { "type": "integer" }
    }
  }
}`
