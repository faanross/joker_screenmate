# Joker Screenmate Architecture

This document describes the system architecture, components, and data flow of Joker Screenmate.

## Overview

Joker Screenmate implements a hybrid C2 channel using:

| Channel | Protocol | Purpose | Bandwidth |
|---------|----------|---------|-----------|
| Primary | DNS (A records) | Beaconing, job detection | Low (~4 bytes/response) |
| Secondary | DNS (TXT records) | Payload delivery | Medium (~200 bytes/chunk) |
| Tertiary | HTTPS | Data exfiltration | High (unlimited) |

## System Components

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TARGET NETWORK                                  │
│                                                                             │
│    ┌──────────────┐                              ┌──────────────────┐       │
│    │    AGENT     │◄─────── A Response ──────────│  LOCAL RESOLVER  │       │
│    │              │         (Job Status)         │                  │       │
│    │  beacon.go   │────── A Query ──────────────►│  (Recursive)     │       │
│    │  https.go    │                              └────────┬─────────┘       │
│    └──────┬───────┘                                       │                 │
│           │                                               │                 │
│           │ TXT Queries (Direct)                          │ A Queries       │
│           │ HTTPS Upload                                  │                 │
└───────────┼───────────────────────────────────────────────┼─────────────────┘
            │                                               │
            │              INTERNET                         │
            │                                               │
┌───────────▼───────────────────────────────────────────────▼─────────────────┐
│                              C2 SERVER                                       │
│                                                                             │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                │
│    │  DNS Server  │◄──►│ Job Manager  │◄──►│HTTPS Server  │                │
│    │   (Port 53)  │    │              │    │ (Port 8443)  │                │
│    │              │    │  Payload     │    │              │                │
│    │  A + TXT     │    │  Chunking    │    │  /upload     │                │
│    │  Records     │    │              │    │  Endpoint    │                │
│    └──────────────┘    └──────────────┘    └──────────────┘                │
│                                                                             │
│    ┌──────────────────────────────────────────────────────┐                │
│    │              Trigger API (localhost:9090)             │                │
│    │              POST /trigger?file=/path                 │                │
│    └──────────────────────────────────────────────────────┘                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Server Components

The C2 server runs three integrated services:

#### 1. DNS Server (`internal/dns/server.go`)

Authoritative DNS server with:
- A record responses indicating job status
- TXT record responses delivering payload chunks
- Thread-safe state management with mutex

```go
type Server struct {
    domain        string
    port          int
    mu            sync.RWMutex
    jobPending    bool          // Current job state
    payloadChunks []string      // Pre-chunked base64 data
    currentChunk  int           // Next chunk to send
    transferDone  bool
}
```

#### 2. HTTPS Server (`internal/https/server.go`)

Receives exfiltrated files:
- Auto-generates self-signed certificates
- Streams uploads to disk
- Adds timestamps to prevent overwrites

#### 3. Trigger API (localhost:9090)

Operator interface for job management:
- `POST /trigger` - Activate default payload
- `POST /trigger?file=/path` - Custom payload
- `GET /status` - Check job state

### Agent Components

The agent runs on the target system:

#### 1. DNS Client (`internal/dns/client.go`)

Handles beacon and payload queries:

```go
type Client struct {
    aTarget   string    // Target for A queries (resolver or C2)
    txtTarget string    // Target for TXT queries (always C2)
    domain    string    // Base domain
    timeout   time.Duration
}
```

**Routing Logic:**
- A queries: Via local resolver (blends with normal traffic)
- TXT queries: Direct to C2 (bypasses resolver caching)

#### 2. HTTPS Client (`internal/https/client.go`)

Handles file exfiltration:
- Skips certificate verification (self-signed)
- Streams files from disk
- No timeout (allows large files)

## Data Flow

### Phase 1: Beaconing

```
AGENT                           LOCAL RESOLVER                    C2 SERVER
  │                                   │                               │
  │─── A Query: www.domain.com ──────►│                               │
  │    (random subdomain rotation)    │                               │
  │                                   │─── Recursive Query ──────────►│
  │                                   │                               │
  │                                   │◄── A Response ────────────────│
  │                                   │    IP: 198.51.100.x (NO JOB)  │
  │◄── A Response ────────────────────│                               │
  │                                   │                               │
  │    [Agent: NO_JOB, sleep 4-6 min] │                               │
```

### Phase 2: Job Detection

```
AGENT                           LOCAL RESOLVER                    C2 SERVER
  │                                   │                               │
  │                                   │         [Operator triggers]   │
  │                                   │         POST /trigger?file=X  │
  │                                   │                               │
  │─── A Query: api.domain.com ──────►│                               │
  │                                   │─── Recursive Query ──────────►│
  │                                   │                               │
  │                                   │◄── A Response ────────────────│
  │                                   │    IP: 203.0.113.x (JOB!)     │
  │◄── A Response ────────────────────│                               │
  │                                   │                               │
  │    [Agent: JOB detected!]         │                               │
```

### Phase 3: TXT Payload Transfer

```
AGENT                                                            C2 SERVER
  │                                                                   │
  │    [Direct TXT queries - bypass resolver]                         │
  │                                                                   │
  │─── TXT Query: verify.domain.com ─────────────────────────────────►│
  │                                                                   │
  │◄── TXT Response: "00000000<base64_chunk_1>" ──────────────────────│
  │                                                                   │
  │    [1.5 second delay]                                             │
  │                                                                   │
  │─── TXT Query: verify.domain.com ─────────────────────────────────►│
  │                                                                   │
  │◄── TXT Response: "00000001<base64_chunk_2>" ──────────────────────│
  │                                                                   │
  │    [Repeat until empty response]                                  │
  │                                                                   │
  │◄── TXT Response: "" (empty = transfer complete) ──────────────────│
```

### Phase 4: HTTPS Exfiltration

```
AGENT                                                            C2 SERVER
  │                                                                   │
  │─── GET /health ──────────────────────────────────────────────────►│
  │                                                                   │
  │◄── 200 OK ────────────────────────────────────────────────────────│
  │                                                                   │
  │─── POST /upload ─────────────────────────────────────────────────►│
  │    Headers:                                                       │
  │      Content-Type: application/octet-stream                       │
  │      X-Filename: employees_dir.zip                                │
  │    Body: [file data stream]                                       │
  │                                                                   │
  │◄── 200 OK ────────────────────────────────────────────────────────│
  │                                                                   │
  │    [Resume beaconing]                                             │
```

## IP Range Signaling

The server uses RFC 5737 documentation ranges for safe simulation:

| IP Range | Meaning | Example |
|----------|---------|---------|
| 198.51.100.0/24 | NO_JOB | 198.51.100.42 |
| 203.0.113.0/24 | JOB_PENDING | 203.0.113.17 |

These ranges are never routed on the public internet, making them safe for testing.

## Subdomain Rotation

Agent rotates through legitimate-looking subdomains:

```go
Subdomains = []string{
    "www", "mail", "app", "docs", "api", "cdn", "assets",
    "static", "portal", "login", "auth", "secure", "support",
    "help", "status", "update", "sync", "time", "ntp", "services",
}
```

This prevents:
- DNS cache hits on repeated queries
- High-entropy subdomain detection
- Pattern-based blocking

## TXT Chunk Format

Payloads are split into ~200 byte chunks with sequence numbers:

```
┌──────────────┬──────────────────────────────────────┐
│ Sequence Num │        Base64 Payload Data           │
│  (8 bytes)   │         (up to ~200 bytes)           │
└──────────────┴──────────────────────────────────────┘
Example: "00000042VGhpcyBpcyBhIHRlc3QgcGF5bG9hZA=="
```

- Sequence number: 8 digits, zero-padded
- Supports up to 99,999,999 chunks
- Base64 encoding for DNS safety

## Security Considerations

### OpSec Features

1. **Jittered Beaconing**: 300 ± 120 seconds (4-6 minutes)
2. **Subdomain Rotation**: 20 legitimate-looking subdomains
3. **Direct TXT Queries**: Bypass resolver caching
4. **Self-Signed TLS**: HTTPS without certificate purchase
5. **RFC 5737 Ranges**: Safe IP ranges for simulation

### Detection Surface

| Indicator | Detection Method |
|-----------|------------------|
| Excessive TXT queries | DNS query type analysis |
| Base64 in TXT responses | Pattern matching |
| RFC 5737 IP ranges | IP reputation/blocklist |
| DNS→HTTPS correlation | Multi-protocol analysis |
| Periodic beaconing | Time-series analysis |

See [Detection Guide](detection-guide.md) for comprehensive detection strategies.

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Beacon Interval | 4-6 minutes |
| TXT Chunk Size | ~200 bytes |
| TXT Query Delay | 1.5 seconds |
| HTTPS Upload | Unlimited (streamed) |

## Next Steps

- [Protocol](protocol.md) - Detailed protocol specification
- [Server Guide](server-guide.md) - Setting up the C2 server
- [Agent Guide](agent-guide.md) - Building and deploying agents
