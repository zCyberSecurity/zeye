# zeye

本地化网络资产测绘引擎。导入外部扫描结果，自动完成 L7 协议探测、指纹识别、GeoIP 富化，存入 Elasticsearch，提供 FOFA 兼容的查询语法。

## 特性

- **20+ 协议探测**：SSH、FTP、HTTP/HTTPS、SMTP、MySQL、PostgreSQL、MongoDB、Redis、SMB、MQTT、Modbus、DNP3 等
- **63 条指纹规则**：覆盖 Web 服务器、CMS、数据库、SSH、FTP、邮件、工控等，自动提取产品版本
- **FOFA 兼容查询**：`=` 包含匹配、`==` 精确匹配、`!=` 排除、`~=` 正则、`^=` 前缀、`$=` 后缀、范围查询
- **GeoIP 地理富化**：可选集成 MaxMind GeoLite2，自动填充国家/省/城市
- **多格式输入**：自动识别 masscan JSON、nmap XML、zmap CSV
- **Elasticsearch 持久化**：scripted upsert 幂等入库，支持增量更新

## 安装

```bash
go install github.com/zCyberSecurity/zeye@latest
```

或从源码编译：

```bash
git clone https://github.com/zCyberSecurity/zeye.git
cd zeye
go build -o zeye .
```

## 快速开始

```bash
# 1. 用外部工具扫描（三选一）
masscan -p 1-65535 192.168.1.0/24 --rate=10000 -oJ scan.json
nmap -p 1-65535 -T4 --open -oX scan.xml 192.168.1.0/24
zmap -p 80 192.168.1.0/24 --output-fields="saddr,dport" -o scan.csv

# 2. 探测 L7 协议 + 指纹识别
zeye probe --input scan.json -o results.json

# 带 GeoIP 富化
zeye probe --input scan.json -o results.json --geoip GeoLite2-City.mmdb

# 3. 入库到 Elasticsearch
zeye import results.json

# 4. 查询
zeye query 'title="admin" && port=80'
```

## CLI 参数

### `zeye probe`

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-i, --input` | (必填) | 扫描结果文件 |
| `-o, --output` | `probe.json` | 输出 JSON 文件 |
| `-f, --format` | `auto` | 输入格式：`auto`/`masscan`/`nmap`/`zmap` |
| `-c, --concurrency` | `100` | 并发探测数 |
| `--timeout` | `8` | 探测超时（秒） |
| `--rules` | 内嵌规则 | 自定义指纹规则目录 |
| `--geoip` | (无) | MaxMind GeoLite2-City.mmdb 路径 |

### `zeye import`

```bash
zeye import results.json            # 使用默认 ES 地址 localhost:9200
zeye import results.json --es http://es-host:9200
```

### `zeye query`

```bash
zeye query 'ip="192.168.0.0/16" && port=443'
zeye query 'app="Nginx" && country="CN"'
zeye query 'title="login" || title="admin"'
```

## 查询语法

兼容 FOFA 查询语法，`=` 为包含匹配。

### 运算符

| 运算符 | 说明 | 示例 |
|---|---|---|
| `=` | 包含匹配（FOFA 兼容） | `title="admin"` |
| `==` | 精确匹配 | `domain=="example.com"` |
| `!=` | 不等于 | `status_code!=404` |
| `*=` | 包含匹配（同 `=`） | `body*="password"` |
| `^=` | 前缀匹配 | `server^="Apache"` |
| `$=` | 后缀匹配 | `domain$=".gov.cn"` |
| `~=` | 正则匹配 | `banner~="OpenSSH_[89]\."` |
| `>` `>=` `<` `<=` | 范围比较 | `port>=8000 && port<=9000` |
| `&&` | 逻辑与 | `port=80 && title="admin"` |
| `\|\|` | 逻辑或 | `port=80 \|\| port=443` |
| `!` | 逻辑非 | `!protocol="ssh"` |
| `()` | 分组 | `(port=80 \|\| port=443) && country="CN"` |

### 查询字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `ip` | ip | IP 地址，支持 CIDR（`ip="10.0.0.0/8"`） |
| `port` | integer | 端口号 |
| `protocol` / `app_proto` | keyword | 应用层协议（http、https、ssh、ftp...） |
| `title` | text | HTML 页面标题 |
| `body` | text | HTTP 响应体 |
| `banner` | text | 协议 banner |
| `server` | keyword | HTTP Server 头 |
| `status_code` / `status` | integer | HTTP 状态码 |
| `header` / `headers` | object | HTTP 响应头 |
| `app` / `fingerprint` | keyword | 指纹名称（`app="Nginx"`） |
| `category` / `categories` | keyword | 产品分类（`category="web-server"`） |
| `tag` / `tags` | keyword | 标签 |
| `cert` / `tls.subject` | keyword | TLS 证书主题 |
| `tls.issuer` | keyword | TLS 证书签发者 |
| `tls.alt_names` | keyword | TLS SAN |
| `tls_expiry` | date | TLS 证书过期时间 |
| `domain` | keyword | 域名（从 TLS SAN 提取） |
| `country` | keyword | 国家代码（需 `--geoip`） |
| `region` | keyword | 省/州（需 `--geoip`） |
| `city` | keyword | 城市（需 `--geoip`） |
| `first_seen` / `last_seen` | date | 首次/最近发现时间 |
| `scan_count` | integer | 扫描发现次数 |

## 输出示例

```json
{
  "ip": "192.168.1.1",
  "port": 22,
  "proto": "tcp",
  "app_proto": "ssh",
  "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
  "fingerprints": ["OpenSSH"],
  "versions": { "OpenSSH": "8.2p1" },
  "categories": ["ssh-server"],
  "tags": ["ssh", "openssh", "remote"],
  "country": "CN",
  "region": "Beijing",
  "city": "Beijing"
}
```

## 内置协议探测器

| 协议 | 端口 |
|---|---|
| SSH | 22, 2222 |
| Telnet | 23 |
| FTP | 21 |
| SMTP/S, IMAP/S, POP3/S | 25/465/587, 143/993, 110/995 |
| SMB | 445, 139 |
| SOCKS5 | 1080, 1081, 10080 |
| NTP (UDP) | 123 |
| Redis | 6379, 6380 |
| Memcached | 11211 |
| MySQL | 3306, 33060 |
| PostgreSQL | 5432 |
| MongoDB | 27017 |
| Oracle TNS | 1521, 1522 |
| MQTT/S | 1883, 8883 |
| Modbus TCP | 502 |
| DNP3 | 20000 |
| HTTP/HTTPS | 所有端口（fallback） |
| TCP banner | 所有端口（fallback） |

## GeoIP 配置

zeye 使用 MaxMind GeoLite2 数据库进行地理位置查询。需要自行下载数据库文件：

1. 注册 [MaxMind 账号](https://www.maxmind.com/en/geolite2/signup)
2. 下载 GeoLite2-City.mmdb
3. 探测时通过 `--geoip` 参数指定路径

```bash
zeye probe --input scan.json -o results.json --geoip /path/to/GeoLite2-City.mmdb
```

## 扩展

### 添加协议探测器

在 `internal/probe/` 下实现 `Prober` 接口，注册到 `engine.go` 的 `NewEngine()` 即可。

### 添加指纹规则

在 `internal/fingerprint/rules/` 下添加 YAML 文件，编译时自动内嵌：

```yaml
- name: vsftpd
  category: ftp-server
  tags: [ftp, vsftpd]
  min_weight: 100
  matches:
    - field: banner
      type: regex
      pattern: "vsFTPd ([\\d.]+)"
      weight: 100
```

## License

MIT
