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

zeye 是一个网络资产测绘平台（类似 FOFA/Shodan），核心是一条流水线：

```
masscan → JSON → 探测（HTTP/TLS/TCP）→ 指纹识别 → SQLite → FOFA-like 查询
```

### 数据流

1. **`internal/masscan/`** — 封装外部 `masscan` 二进制。`runner.go` 启动进程并通过 channel 流式输出 `ScanResult`（ip、port、proto）；`parser.go` 解析 masscan 的 JSON 输出（NDJSON，每行一个对象）。

2. **`internal/probe/`** — 并发探测引擎。`engine.go` 用 goroutine pool 消费 `ScanResult` channel，输出 `ProbeResult` channel。`Prober` 接口（`prober.go`）是扩展新协议的入口。`http.go` 处理 HTTP/HTTPS，自动协商 scheme 并提取 TLS 证书；`tcp.go` 抓取原始 banner 并按端口/banner 特征猜测协议。

3. **`internal/fingerprint/`** — 基于规则的指纹引擎。规则为 YAML 文件，通过 `loader.go` 中的 `//go:embed rules/*.yaml` 编译时内嵌。引擎对所有规则并发匹配，按权重累加评分。规则支持的 field：`header.<名称>`、`body`、`title`、`banner`、`server`、`tls.subject`、`tls.issuer`、`status_code`、`app_proto`。

4. **`internal/store/`** — 使用 `modernc.org/sqlite`（纯 Go，无 CGO）持久化。`db.go` 提供 `Upsert`（ON CONFLICT 更新）和 `Query`。`ip_int` 列将 IPv4 存为 uint32，使 CIDR 范围查询走 `BETWEEN` 整数比较。`fingerprints`/`tags` 等 JSON 数组列通过 SQLite 的 `json_each()` 查询。

5. **`internal/query/`** — FOFA-like 查询解析流水线：`lexer.go` 词法分析 → `parser.go` 递归下降构建 AST（节点定义在 `ast.go`）→ `translator.go` 将 AST 翻译为 SQL WHERE 子句 + `[]interface{}` 参数。翻译器自动处理 CIDR→ip_int 范围转换和数组字段的 json_each 子查询。

### 查询字段映射

| 查询字段 | SQL 列 | 说明 |
|---|---|---|
| `ip` | `ip` / `ip_int` | CIDR 自动转为 `BETWEEN` |
| `port`、`status_code`、`scan_count` | 数值列 | 仅支持数值比较运算符 |
| `fingerprint` / `app` | `fingerprints` | `json_each()` 子查询 |
| `tag` | `tags` | `json_each()` 子查询 |
| `tls.subject` / `cert` | `tls_subject` | 点号语法映射 |
| `protocol` / `app_proto` | `app_proto` | |

### 扩展新协议探测器

实现 `probe.Prober` 接口，在 `engine.Run()` 前调用 `engine.Register(p)` 注册。`ShouldProbe(port uint16) bool` 方法控制该探测器作用于哪些端口。

### 新增指纹规则

在 `internal/fingerprint/rules/` 下添加 `.yaml` 文件，编译时自动内嵌。格式为 `Rule` 对象数组，字段包括 `name`、`category`、`tags`、`min_weight`，以及 `matches`（每条包含 `field`、`type` [keyword/regex/equals]、`pattern`/`value`、`weight`）。
