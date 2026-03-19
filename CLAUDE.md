# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 常用命令

```bash
# 编译
go build -o zeye .

# 编译并运行
go run . <命令>

# 同步依赖
go mod tidy

# 运行所有测试
go test ./...

# 运行指定包的测试
go test ./internal/query/...

# 静态检查
go vet ./...
```

## 架构概览

zeye 是一个本地化网络资产测绘引擎，核心是一条流水线：

```
外部扫描（masscan/nmap/zmap）→ 导入/去重 → L7 探测 → 指纹识别 → GeoIP 富化 → Elasticsearch → FOFA-like 查询
```

zeye **不触发**任何扫描，由用户自行使用外部工具完成端口扫描，再将结果文件导入 zeye 处理。

### 典型工作流

```bash
# 1. 用外部工具扫描（用户自行完成，三选一）
masscan -p 1-65535 192.168.1.0/24 --rate=10000 -oJ scan.json
nmap -p 1-65535 -T4 --open -oX scan.xml 192.168.1.0/24
zmap -p 80 192.168.1.0/24 --output-fields="saddr,dport" -o scan.csv

# 2. 探测 L7 协议，输出结构化 JSON（可选 --geoip 富化地理信息）
zeye probe --input scan.json -o results.json --geoip GeoLite2-City.mmdb

# 3. 将探测结果入库
zeye import results.json

# 4. 查询（= 为包含匹配，兼容 FOFA 语法）
zeye query 'title="admin" && port=80'
```

### 数据流

1. **`internal/input/`** — 统一扫描结果解析层。
   - `parser.go`：`ParseFile(path, format)` 自动检测格式，流式输出去重后的 `ScanResult`（ip、port、proto）
   - `masscan.go`：解析 masscan NDJSON/array JSON
   - `nmap.go`：解析 nmap `-oX` XML
   - `zmap.go`：解析 zmap CSV（需含 `saddr`/`dport` 字段；运行 zmap 时加 `--output-fields="saddr,dport"`）
   - `Dedup()`：对 `ip:port:proto` 三元组去重

   **格式自动检测**：`<?xml`/`<nmaprun` → nmap；`[`/`{` 开头 → masscan；其他 → zmap CSV。

2. **`internal/probe/`** — 并发 L7 探测引擎。职责是**采集原始协议数据**，不做产品识别。

   - `engine.go`：goroutine pool，消费 `input.ScanResult` channel，输出 `ProbeResult` channel。
     初始化时对所有探测器调用 `ShouldProbe` 建立 `portIndex map[uint16][]Prober`，探测时 O(1) 查找专属探测器；专属探测器全部失败后降级到 HTTP → TCP fallback，端口信息必然被记录。
   - `prober.go`：`Prober` 接口（`Protocol()`、`ShouldProbe(port)`、`Probe(ctx, ip, port)`）
   - `util.go`：`dialTCP`、`dialTLS`、`readFull`、`tlsCertInfo`（TLS 证书提取）、`bsonString`（BSON 字段扫描）

   **ProbeResult 字段说明**：
   - `Banner`：完整的原始协议 banner，由各 prober 负责尽可能丰富（如 `"Redis 7.0.11"`、`"MySQL 8.0.27"`、`"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"`）。版本信息**不单独提字段**，由 fingerprint 层通过 regex 从 banner 提取。
   - `TLSSubject/TLSIssuer/TLSAltNames/TLSExpiry`：TLS 证书信息，HTTP/HTTPS 以及 TLS 包装的邮件/MQTT 协议均会填充。

   **HTTPS 检测增强**：HTTP 探测器收到 `"Client sent an HTTP request to an HTTPS server"` 响应时，自动尝试 HTTPS；若 HTTPS 握手失败，仍将 `app_proto` 标记为 `https`（基于服务器明确声明）。TCP fallback 探测器能识别 `HTTP/` 开头的 banner 并标记为 `http`。

   **内置探测器与对应端口**：

   | 文件 | 协议 | 端口 |
   |---|---|---|
   | `ssh.go` | SSH | 22, 2222 |
   | `telnet.go` | Telnet | 23 |
   | `ftp.go` | FTP | 21 |
   | `mail.go` | SMTP/S, IMAP/S, POP3/S | 25/465/587, 143/993, 110/995 |
   | `smb.go` | SMB, SMB2 | 445, 139 |
   | `socks5.go` | SOCKS5 | 1080, 1081, 10080 |
   | `ntp.go` | NTP (UDP) | 123 |
   | `redis.go` | Redis | 6379, 6380 |
   | `memcached.go` | Memcached | 11211 |
   | `mysql.go` | MySQL | 3306, 33060 |
   | `postgresql.go` | PostgreSQL | 5432 |
   | `mongodb.go` | MongoDB | 27017 |
   | `oracle.go` | Oracle TNS | 1521, 1522 |
   | `mqtt.go` | MQTT/S | 1883, 8883 |
   | `modbus.go` | Modbus TCP | 502 |
   | `dnp3.go` | DNP3 | 20000 |
   | `http.go` | HTTP/HTTPS (fallback) | 所有端口（httpsPorts: 443, 6443, 8443, 4443, 10443） |
   | `tcp.go` | TCP banner grab (fallback) | 所有端口 |

3. **`internal/fingerprint/`** — 基于规则的指纹引擎。职责是**解释 ProbeResult 原始数据，识别产品和版本**。

   **协议 vs 产品的分工**：probe 层识别协议（`AppProto = "ftp"`），fingerprint 层识别产品（`vsftpd 3.0.3`、`ProFTPD`...）。一个协议可对应多个产品实现，fingerprint 规则通过 banner 特征区分。

   规则为 YAML 文件，通过 `loader.go` 中的 `//go:embed rules/*.yaml` 编译时内嵌。引擎对所有规则并发匹配，按权重累加评分，超过 `min_weight` 则命中，输出 `MatchResult{Name, Category, Version, Tags, Confidence}`。

   **规则支持的 field**：`header.<名称>`、`body`、`title`、`banner`、`server`、`tls.subject`、`tls.issuer`、`status_code`、`app_proto`。

   **版本提取**：`type: regex` 规则的第一个捕获组自动填入 `MatchResult.Version`，无需 probe 层预处理。版本信息通过 `Asset.Versions` (`map[string]string`) 传递到输出和 ES。

   **当前覆盖的产品**（63 条规则）：
   - Web 服务器：Nginx、Apache、IIS、Tomcat、Weblogic
   - CMS/框架：WordPress、Drupal、Joomla、Laravel、Spring Boot、Django、PHP
   - SSH：OpenSSH、Dropbear、Bitvise、libssh、Cisco SSH
   - FTP：vsftpd、ProFTPD、Pure-FTPd、FileZilla Server、Microsoft FTP
   - 邮件：Postfix、Exim、Sendmail、Exchange、Dovecot、Cyrus、Courier
   - 数据库：MySQL、MariaDB、Percona、PostgreSQL、MongoDB、Redis、Memcached、Oracle
   - 工控：Modbus TCP、DNP3
   - 其他：SMB/Samba、MQTT/Mosquitto/EMQX、SOCKS5、NTP、Telnet、Shiro、Kibana、Grafana、Jenkins、GitLab、Prometheus、MinIO、phpMyAdmin、Hikvision、Dahua

4. **`internal/geo/`** — GeoIP 地理位置查询。封装 `github.com/oschwald/geoip2-golang`，通过 MaxMind GeoLite2-City.mmdb 数据库查询 IP 对应的国家（ISO 3166-1 alpha-2）、省/州、城市。通过 `--geoip` 参数可选启用。

5. **`internal/store/`** — 使用 `github.com/elastic/go-elasticsearch/v8` 对接 Elasticsearch 持久化，索引名 `zeye-assets`。`db.go` 提供：
   - `Open(addr)` — 连接 ES 并确保索引及 mapping 存在（`schema.go` 定义 mapping，3 shard / 1 replica）
   - `Upsert` — scripted upsert：首次写入完整文档，重复发现时通过 Painless 脚本增量更新字段并累加 `scan_count`，冲突自动重试 3 次
   - `AssetFromProbeResult` — 将 ProbeResult + 指纹匹配结果转换为 Asset，提取 versions、categories、domain（从 TLS SAN）
   - `Query(dsl, opts)` — 接收 ES Query DSL map，返回 `[]*Asset`，支持分页（`Limit`/`Offset`）和排序（`OrderBy`）
   - `Count(dsl)` — 返回匹配文档数
   - 文档 ID 由 `md5(ip:port:proto)` 生成，保证幂等

6. **`internal/query/`** — FOFA 兼容查询解析流水线：`lexer.go` 词法分析 → `parser.go` 递归下降构建 AST（节点定义在 `ast.go`）→ `translator.go` 将 AST 翻译为 **Elasticsearch Query DSL**（`map[string]interface{}`）。

   **运算符语义（兼容 FOFA）**：
   - `=`：包含匹配（text 字段用 `match`，keyword 字段用 `wildcard *value*`），与 FOFA 的 `=` 语义一致
   - `==`：精确匹配（text 字段用 `match_phrase`，keyword 字段用 `term`）
   - `!=`：不等于（精确匹配的取反）
   - `*=`：同 `=`，显式包含匹配
   - `^=`：前缀匹配（`prefix` 查询）
   - `$=`：后缀匹配（`wildcard *value`）
   - `~=`：正则匹配（`regexp` 查询，大小写不敏感）
   - `>` `>=` `<` `<=`：范围查询（数值/日期）

### CLI 命令

| 命令 | 说明 |
|---|---|
| `zeye probe -i <file> -o results.json` | 探测并输出 JSON，支持 `--format auto/masscan/nmap/zmap`、`--geoip <mmdb>` |
| `zeye import <file>` | 将 probe 产出的 JSON 入库到 ES |
| `zeye query '<expr>'` | FOFA 式查询 |

### 查询字段映射

| 查询字段 | ES 字段 | 类型 | 说明 |
|---|---|---|---|
| `ip` | `ip` | `ip` | 支持 CIDR |
| `port`、`status_code`、`scan_count` | 同名 | `integer` | 数值比较用 range 查询 |
| `fingerprint` / `app` / `fingerprints` | `fingerprints` | `keyword` | |
| `category` / `categories` | `categories` | `keyword` | 指纹规则中的产品分类 |
| `tag` / `tags` | `tags` | `keyword` | |
| `tls.subject` / `cert` | `tls_subject` | `keyword` | |
| `tls.issuer` | `tls_issuer` | `keyword` | |
| `tls.alt_names` | `tls_alt_names` | `keyword` | |
| `protocol` / `app_proto` | `app_proto` | `keyword` | |
| `title` | `title` | `text` + keyword | |
| `body`、`banner` | 同名 | `text` | `=` 用 match，`==` 用 match_phrase |
| `domain` | `domain` | `keyword` | 从 TLS SAN 提取 |
| `country` | `country` | `keyword` | GeoIP 国家代码 |
| `region` | `region` | `keyword` | GeoIP 省/州 |
| `city` | `city` | `keyword` | GeoIP 城市 |
| `first_seen`、`last_seen`、`tls_expiry` | 同名 | `date` | 支持范围比较 |

### 扩展新协议探测器

1. 在 `internal/probe/` 下新建 `<proto>.go`，实现 `Prober` 接口：
   - `Protocol() string` — 协议标识符（小写，如 `"ssh"`）
   - `ShouldProbe(port uint16) bool` — 声明该探测器负责哪些端口
   - `Probe(ctx, ip, port) (*ProbeResult, error)` — 实际探测逻辑；无法确认协议时返回 `nil, error`
2. 在 `engine.go` 的 `NewEngine()` 中将新探测器加入 `specific` 切片。
3. 无需关心优先级，`engine` 初始化时自动建立端口索引。

### 新增指纹规则

在 `internal/fingerprint/rules/` 下添加 `.yaml` 文件，编译时自动内嵌。

```yaml
- name: vsftpd
  category: ftp-server
  tags: [ftp, vsftpd]
  min_weight: 100
  matches:
    - field: banner
      type: regex
      pattern: "vsFTPd ([\d.]+)"   # 捕获组 → MatchResult.Version
      weight: 100
```

字段说明：
- `require_all: true` — 所有 match 条件必须全部命中（默认 false，累加权重）
- `type` 取值：`keyword`（不区分大小写 contains）、`regex`（第一捕获组为版本）、`equals`（不区分大小写全匹配）
- 规则命中条件：`matchedWeight >= min_weight`
- `category` 会自动传递到 Asset 的 `categories` 字段，可通过 `category="ssh-server"` 查询
