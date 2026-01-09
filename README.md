# Joker Screenmate: DNS Tunnel C2 Simulator

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://golang.org/) [![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE) [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/)

> **WARNING: EDUCATIONAL PURPOSE ONLY**
>
> This tool is designed exclusively for security research, threat hunting education, and authorized penetration testing. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.

## Overview

Joker Screenmate is a proof-of-concept Command and Control (C2) simulator that demonstrates covert data exfiltration using DNS tunneling with TXT records for payload delivery and HTTPS for file uploads. The project serves as an educational tool for cybersecurity professionals, threat hunters, and network defenders to understand and detect advanced DNS-based evasion techniques.

### Key Features

- **DNS-Based C2 Communication**: Leverages DNS A and TXT records for covert command and control
- **TXT Record Payload Delivery**: Transfers payloads via base64-encoded TXT record chunks
- **HTTPS Exfiltration Channel**: Uploads files to C2 via encrypted HTTPS connection
- **Job Signaling via IP Ranges**: Uses RFC 5737 documentation IP ranges to signal job status
- **Cross-Platform Agent**: Agent supports Windows targets, server runs on Linux
- **Jittered Beaconing**: Randomized timing (configurable interval +/- jitter) to evade pattern-based detection
- **Direct vs. Resolver Mode**: A queries can go through local DNS resolver or direct to C2
- **Self-Signed TLS**: Auto-generates certificates for HTTPS communications
- **Low-Entropy Subdomains**: Uses legitimate-looking subdomain rotation to avoid detection

## Quick Start

### Prerequisites

- Go 1.23 or higher
- **Linux Server**: Root privileges for binding to port 53
- **Windows Agent**: No special privileges required
- Domain with NS records pointing to your server (for resolver mode)

### Installation

```bash
# Clone the repository
git clone https://github.com/faanross/joker_screenmate.git
cd joker_screenmate

# Install dependencies
go mod download

# Build server (Linux)
GOOS=linux go build -o server ./cmd/server

# Build agent (Windows)
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

### Configuration

#### Server Configuration

Edit `cmd/server/main.go`:

```go
var (
    Domain      = "timeserversync.com"    // Your domain
    PayloadFile = "./payloads/payload.jpg" // File to transfer via TXT
    CertDir     = "./certs"                // TLS certificate directory
    DNSPort     = 53                       // DNS server port
    HTTPSPort   = 8443                     // HTTPS upload port
    TriggerPort = 9090                     // Local API trigger port
    ExfilDir    = "./exfiltrated"          // Received files directory
)
```

#### Agent Configuration

Edit `cmd/agent/main.go`:

```go
var (
    Domain         = "timeserversync.com"         // Must match server
    C2ServerIP     = "192.168.1.100"              // Server IP (REQUIRED)
    DirectMode     = false                        // true=direct to C2, false=via resolver
    DNSResolver    = "192.168.2.1:53"             // Local resolver for A queries
    BeaconInterval = 300                          // Base interval (seconds)
    Jitter         = 120                          // +/- randomization (seconds)
    HTTPSPort      = 8443                         // HTTPS upload port
    ExfilFilePath  = `C:\path\to\file.zip`        // File to exfiltrate
    TXTQueryDelayMs = 1500                        // Delay between TXT queries (ms)
)
```

**Routing Modes:**
- **Direct Mode (testing)**: All DNS queries go directly to C2 server
- **Resolver Mode (production)**: A queries go through local resolver, TXT queries always direct to C2

### Running the Demo

**On Linux Server:**

```bash
sudo ./server
```

**Trigger a Job:**

```bash
# Default payload
curl -X POST http://localhost:9090/trigger

# Custom payload
curl -X POST "http://localhost:9090/trigger?file=/path/to/payload"

# Check status
curl http://localhost:9090/status
```

**On Windows Agent:**

```powershell
.\agent.exe
```

## How It Works

### DNS Tunneling with TXT Records

The C2 communication leverages DNS in two ways:

1. **A Record Beacons**: Agent queries A records to check for pending jobs. The server responds with IP addresses from specific ranges:
   - `198.51.100.0/24` = No job pending
   - `203.0.113.0/24` = Job ready (RFC 5737 documentation ranges)

2. **TXT Record Transfer**: When a job is triggered, the server chunks the payload into base64-encoded TXT records. Each chunk includes an 8-digit sequence number prefix for ordering.

### HTTPS Exfiltration

After receiving the TXT payload, the agent uploads a configured file to the C2 server over HTTPS. The server uses self-signed certificates with auto-generation if missing.

### Communication Flow

```
┌─────────────────────┐                    ┌─────────────────────┐
│       Agent         │                    │       Server        │
│     (Windows)       │                    │      (Linux)        │
└──────────┬──────────┘                    └──────────┬──────────┘
           │                                          │
           │   1. A Query: www.timeserversync.com     │
           │ ─────────────────────────────────────────►
           │                                          │
           │   2. A Response: 198.51.100.x (NO JOB)   │
           │ ◄─────────────────────────────────────────
           │                                          │
           │          [Sleep 4-6 minutes]             │
           │                                          │
           │   3. A Query: api.timeserversync.com     │
           │ ─────────────────────────────────────────►
           │                                          │  ← Job triggered
           │   4. A Response: 203.0.113.x (JOB!)      │
           │ ◄─────────────────────────────────────────
           │                                          │
           │   5. TXT Query: verify.timeserversync.com│
           │ ─────────────────────────────────────────►
           │                                          │
           │   6. TXT Response: "00000000<base64>"    │
           │ ◄─────────────────────────────────────────
           │                                          │
           │          [Repeat TXT queries...]         │
           │                                          │
           │   7. TXT Response: "" (empty = done)     │
           │ ◄─────────────────────────────────────────
           │                                          │
           │   8. HTTPS POST /upload (file)           │
           │ ═════════════════════════════════════════►
           │                                          │
           │   9. HTTPS 200 OK                        │
           │ ◄═════════════════════════════════════════
           │                                          │
           │        [Resume beacon cycle]             │
           ▼                                          ▼
```

### TXT Record Chunk Format

```
┌──────────────┬──────────────────────────────────────┐
│ Sequence Num │        Base64 Payload Data           │
│  (8 bytes)   │         (up to ~200 bytes)           │
└──────────────┴──────────────────────────────────────┘
     Example: "00000042VGhpcyBpcyBhIHRlc3QgcGF5bG9hZA=="
```

## Detection Guide

### Network-Based Detection

#### DNS Anomalies

**Detection Indicators:**
- High volume of TXT queries to a single domain
- TXT responses containing base64-encoded data
- A record responses using RFC 5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24)
- Regular beacon patterns despite jitter (statistical analysis)
- Long TXT record values (legitimate TXT records are usually short)

**Suricata Rules:**

```
# Detect DNS TXT query patterns
alert dns any any -> any any (msg:"Possible DNS Tunnel - Excessive TXT Queries";
    dns.query; content:".timeserversync.com"; dns_query;
    threshold:type both,track by_src,count 50,seconds 300;
    sid:1000001; rev:1;)

# Detect job signaling IP ranges
alert dns any any -> any any (msg:"Possible C2 Job Signal - RFC5737 Range";
    dns.answer; content:"203.0.113";
    sid:1000002; rev:1;)
```

**Zeek Detection:**

```zeek
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
    if (is_orig && msg$qtype == DNS_TXT)
    {
        # Track TXT query frequency per source
        if (c$id$orig_h in txt_query_count)
            ++txt_query_count[c$id$orig_h];
        else
            txt_query_count[c$id$orig_h] = 1;

        if (txt_query_count[c$id$orig_h] > 100)
            NOTICE([$note=DNS_Tunnel_Suspected,
                    $msg=fmt("High TXT query rate from %s", c$id$orig_h)]);
    }
}
```

#### HTTPS Exfiltration Detection

**Indicators:**
- HTTPS connections to non-standard ports (8443)
- Self-signed certificates
- Large POST requests to /upload endpoints
- Connection to IP after DNS tunnel activity

### Host-Based Detection

#### Process Behavior

**Detection Points:**
- Process making DNS queries followed by HTTPS uploads
- Executable with DNS client library dependencies
- Process sleeping for extended periods between network activity
- Configuration files containing IP addresses and domain names

**Windows Event IDs:**
- 5156: Windows Filtering Platform allowed connection (DNS port 53)
- 5157: Windows Filtering Platform blocked connection
- 3: Sysmon Network Connection (correlate DNS + HTTPS)

**Sysmon Configuration:**

```xml
<RuleGroup name="Joker Screenmate Detection" groupRelation="or">
    <NetworkConnect onmatch="include">
        <DestinationPort condition="is">53</DestinationPort>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
        <DestinationPort condition="is">8443</DestinationPort>
    </NetworkConnect>
    <DnsQuery onmatch="include">
        <QueryName condition="contains">timeserversync.com</QueryName>
    </DnsQuery>
</RuleGroup>
```

### Threat Hunting Queries

```sql
-- Hunt for DNS tunnel patterns
SELECT
    src_ip,
    domain,
    COUNT(CASE WHEN query_type = 'TXT' THEN 1 END) as txt_count,
    COUNT(CASE WHEN query_type = 'A' THEN 1 END) as a_count,
    AVG(response_size) as avg_response_size
FROM dns_logs
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY src_ip, domain
HAVING txt_count > 50
    OR (txt_count > 10 AND a_count > 5);

-- Correlate DNS activity with HTTPS uploads
SELECT DISTINCT d.src_ip, d.domain, h.dest_ip, h.dest_port, h.bytes_sent
FROM dns_logs d
JOIN https_logs h ON d.src_ip = h.src_ip
    AND h.timestamp BETWEEN d.timestamp AND d.timestamp + INTERVAL '5 minutes'
WHERE d.query_type = 'TXT'
    AND h.dest_port = 8443
    AND h.method = 'POST';
```

## Mitigation Strategies

### Network Controls

1. **DNS Monitoring**
   - Monitor for excessive TXT queries
   - Alert on base64 patterns in DNS responses
   - Block queries to known-bad domains

2. **Egress Filtering**
   - Restrict outbound DNS to approved resolvers
   - Block direct DNS (port 53) to external IPs
   - Monitor/block non-standard HTTPS ports

3. **TLS Inspection**
   - Inspect HTTPS traffic for data exfiltration
   - Block self-signed certificates to unknown hosts

### Host Controls

1. **Application Whitelisting**
   - Restrict executables with DNS capabilities
   - Monitor for unsigned binaries making network connections

2. **Endpoint Detection**
   - Correlate DNS and HTTPS activity per process
   - Alert on beacon-like timing patterns

## Project Structure

```
joker_screenmate/
├── cmd/
│   ├── agent/
│   │   └── main.go          # Agent entry point (Windows)
│   └── server/
│       └── main.go          # Server entry point (Linux)
├── internal/
│   ├── dns/
│   │   ├── client.go        # Agent DNS query logic
│   │   └── server.go        # Authoritative DNS server
│   ├── https/
│   │   ├── client.go        # Agent HTTPS upload client
│   │   └── server.go        # HTTPS file receiver
│   └── protocol/
│       └── protocol.go      # Shared constants and utilities
├── certs/                   # TLS certificates (auto-generated)
├── payloads/                # Sample payload files
├── exfiltrated/             # Received exfiltrated files
├── go.mod
├── go.sum
└── README.md
```

## Legal Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool. The authors assume no liability for misuse or damage caused by this program.

**By using this software, you agree to:**

- Use it only in authorized environments
- Comply with all applicable laws and regulations
- Take full responsibility for your actions
- Not use it for malicious purposes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by real-world DNS tunneling techniques used in APT campaigns
- Built for the cybersecurity education community
- Thanks to the miekg/dns library maintainers

## References

- [DNS RFC 1035](https://tools.ietf.org/html/rfc1035)
- [RFC 5737 - IPv4 Address Blocks Reserved for Documentation](https://tools.ietf.org/html/rfc5737)
- [MITRE ATT&CK - Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK - Application Layer Protocol: DNS (T1071.004)](https://attack.mitre.org/techniques/T1071/004/)
- [SANS - Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)

## Contact

For questions, issues, or security concerns, please open an issue on GitHub.
