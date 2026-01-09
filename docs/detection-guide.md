# Joker Screenmate Detection Guide

This guide covers detection strategies for Joker Screenmate DNS tunnel traffic.

## Detection Overview

| Indicator | Detection Difficulty | Confidence |
|-----------|---------------------|------------|
| RFC 5737 IP ranges | Easy | High |
| Excessive TXT queries | Easy | Medium |
| Base64 in TXT records | Medium | High |
| Periodic beaconing | Medium | Medium |
| DNS→HTTPS correlation | Medium | High |

## Network-Based Detection

### 1. RFC 5737 Documentation Ranges

The server responds with IPs from RFC 5737 documentation ranges, which should never appear in production traffic.

#### Suricata Rules

```
# Detect RFC 5737 TEST-NET-2 range in DNS responses
alert dns any any -> any any (
    msg:"JOKER-C2 - RFC 5737 TEST-NET-2 in DNS response";
    dns.type:A;
    content:"|c6|";  # 198 in hex (198.51.100.x)
    offset:0;
    depth:1;
    pcre:"/198\.51\.100\.\d+/";
    classtype:trojan-activity;
    sid:1000001;
    rev:1;
)

# Detect RFC 5737 TEST-NET-3 range in DNS responses
alert dns any any -> any any (
    msg:"JOKER-C2 - RFC 5737 TEST-NET-3 in DNS response (JOB signal)";
    dns.type:A;
    content:"|cb|";  # 203 in hex (203.0.113.x)
    offset:0;
    depth:1;
    pcre:"/203\.0\.113\.\d+/";
    classtype:trojan-activity;
    sid:1000002;
    rev:1;
)
```

#### Zeek Script

```zeek
# rfc5737_detection.zeek
module RFC5737_Detection;

export {
    redef enum Notice::Type += {
        RFC5737_Response
    };
}

# RFC 5737 documentation ranges
const test_net_2 = 198.51.100.0/24;
const test_net_3 = 203.0.113.0/24;

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    if (a in test_net_2 || a in test_net_3) {
        NOTICE([
            $note=RFC5737_Response,
            $msg=fmt("RFC 5737 documentation IP in DNS response: %s", a),
            $conn=c,
            $identifier=cat(c$id$orig_h, a)
        ]);
    }
}
```

### 2. Excessive TXT Query Detection

TXT queries during payload transfer create a detectable burst pattern.

#### Zeek Script

```zeek
# txt_burst_detection.zeek
module TXT_Burst;

export {
    redef enum Notice::Type += {
        TXT_Query_Burst
    };

    const burst_threshold = 10 &redef;
    const time_window = 60sec &redef;
}

global txt_queries: table[addr] of count &default=0 &create_expire=60sec;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (qtype == 16) {  # TXT record
        local client = c$id$orig_h;
        ++txt_queries[client];

        if (txt_queries[client] >= burst_threshold) {
            NOTICE([
                $note=TXT_Query_Burst,
                $msg=fmt("TXT query burst from %s: %d queries in window",
                        client, txt_queries[client]),
                $conn=c
            ]);
        }
    }
}
```

#### Splunk Query

```spl
index=dns sourcetype=dns qtype=TXT
| bin _time span=1m
| stats count as txt_count by src_ip, _time
| where txt_count > 10
| stats sum(txt_count) as total_txt,
        avg(txt_count) as avg_per_min,
        max(txt_count) as peak_per_min
  by src_ip
| where total_txt > 50
| sort -total_txt
```

### 3. Base64 Detection in TXT Records

Payload chunks contain Base64-encoded data with sequence prefixes.

#### Python Detection Script

```python
#!/usr/bin/env python3
"""Detect Base64 content in DNS TXT records."""

import re
from scapy.all import sniff, DNS, DNSRR

# Pattern: 8 digits followed by Base64
JOKER_PATTERN = re.compile(r'^\d{8}[A-Za-z0-9+/]+=*$')

# Generic Base64 pattern
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

def analyze_txt(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # Response
        for i in range(pkt[DNS].ancount):
            rr = pkt[DNS].an[i]
            if rr.type == 16:  # TXT
                txt_data = rr.rdata.decode('utf-8', errors='ignore')

                # Check for Joker pattern
                if JOKER_PATTERN.match(txt_data):
                    print(f"[ALERT] Joker C2 TXT detected!")
                    print(f"  Query: {pkt[DNS].qd.qname.decode()}")
                    print(f"  TXT: {txt_data[:50]}...")
                    print(f"  Sequence: {txt_data[:8]}")

                # Check for generic Base64
                elif BASE64_PATTERN.match(txt_data):
                    print(f"[WARN] Base64-like TXT record")
                    print(f"  Query: {pkt[DNS].qd.qname.decode()}")
                    print(f"  Length: {len(txt_data)}")

if __name__ == "__main__":
    print("Monitoring for Base64 in TXT records...")
    sniff(filter="udp port 53", prn=analyze_txt, store=0)
```

#### Zeek Script

```zeek
# base64_txt_detection.zeek
module Base64_TXT;

export {
    redef enum Notice::Type += {
        Base64_TXT_Record
    };
}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, txt: string) {
    # Check for Joker pattern: 8 digits + base64
    if (/^[0-9]{8}[A-Za-z0-9+\/]+=*$/ in txt) {
        NOTICE([
            $note=Base64_TXT_Record,
            $msg=fmt("Joker C2 TXT pattern detected: %s", ans$query),
            $conn=c,
            $identifier=cat(c$id$orig_h, ans$query)
        ]);
    }
    # Check for generic base64
    else if (/^[A-Za-z0-9+\/]{20,}={0,2}$/ in txt && |txt| > 50) {
        NOTICE([
            $note=Base64_TXT_Record,
            $msg=fmt("Base64-like TXT record: %s (%d bytes)", ans$query, |txt|),
            $conn=c
        ]);
    }
}
```

### 4. Fixed "verify" Subdomain

TXT queries always use the "verify" subdomain.

#### Suricata Rule

```
alert dns any any -> any any (
    msg:"JOKER-C2 - TXT query to verify subdomain";
    dns.query;
    content:"verify.";
    nocase;
    dns.type:TXT;
    classtype:trojan-activity;
    sid:1000003;
    rev:1;
)
```

### 5. DNS→HTTPS Correlation

Job completion triggers immediate HTTPS upload.

#### Splunk Correlation

```spl
# Find DNS queries followed by HTTPS uploads
index=dns sourcetype=dns query="*timeserversync*"
| rename src_ip as client
| join client [
    search index=proxy sourcetype=proxy method=POST uri="/upload"
    | rename src_ip as client
]
| where _time_http - _time_dns < 300
| stats count by client, query, dest_ip, uri
| where count > 0
```

#### Zeek Correlation

```zeek
# dns_https_correlation.zeek
module DNS_HTTPS_Correlation;

export {
    redef enum Notice::Type += {
        DNS_HTTPS_Exfil_Pattern
    };
}

# Track DNS queries
global dns_queries: table[addr] of set[string] &create_expire=5min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    local client = c$id$orig_h;
    if (client !in dns_queries)
        dns_queries[client] = set();
    add dns_queries[client][query];
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local client = c$id$orig_h;

    # Check for upload after DNS query
    if (method == "POST" && /upload/ in original_URI) {
        if (client in dns_queries && |dns_queries[client]| > 0) {
            NOTICE([
                $note=DNS_HTTPS_Exfil_Pattern,
                $msg=fmt("HTTPS upload after DNS queries from %s", client),
                $conn=c
            ]);
        }
    }
}
```

### 6. Beacon Pattern Detection

Jittered beaconing creates detectable timing patterns.

#### Python Beacon Detector

```python
#!/usr/bin/env python3
"""Detect periodic DNS beaconing patterns."""

import statistics
from collections import defaultdict
from datetime import datetime, timedelta

class JokerBeaconDetector:
    def __init__(self):
        self.queries = defaultdict(list)
        self.min_samples = 5
        # Joker beacon: 180-420 seconds (3-7 minutes)
        self.expected_min = 180
        self.expected_max = 420

    def add_query(self, src_ip, domain, timestamp):
        key = (src_ip, self._extract_base_domain(domain))
        self.queries[key].append(timestamp)

    def _extract_base_domain(self, domain):
        parts = domain.rstrip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def analyze(self):
        suspicious = []
        for (src_ip, domain), times in self.queries.items():
            if len(times) < self.min_samples:
                continue

            times = sorted(times)
            intervals = [(times[i+1] - times[i]).total_seconds()
                        for i in range(len(times)-1)]

            if not intervals:
                continue

            mean = statistics.mean(intervals)

            # Check if intervals match Joker timing
            if self.expected_min <= mean <= self.expected_max:
                stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                suspicious.append({
                    'src_ip': src_ip,
                    'domain': domain,
                    'count': len(times),
                    'mean_interval': mean,
                    'stdev': stdev,
                    'pattern': 'JOKER_BEACON'
                })

        return suspicious
```

## Host-Based Detection

### Sysmon Configuration

```xml
<Sysmon schemaversion="4.50">
    <EventFiltering>
        <!-- DNS queries -->
        <DnsQuery onmatch="include">
            <QueryName condition="contains">timeserversync</QueryName>
            <QueryName condition="contains">verify.</QueryName>
        </DnsQuery>

        <!-- Network connections -->
        <NetworkConnect onmatch="include">
            <DestinationPort condition="is">53</DestinationPort>
            <DestinationPort condition="is">8443</DestinationPort>
        </NetworkConnect>

        <!-- Process with network activity -->
        <ProcessCreate onmatch="include">
            <Image condition="contains">agent</Image>
        </ProcessCreate>
    </EventFiltering>
</Sysmon>
```

### Windows Event Queries

```powershell
# Find DNS queries to suspicious domains
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-DNS-Client/Operational'
    Id = 3008
} | Where-Object {
    $_.Message -match 'timeserversync|verify\.'
}

# Find unusual HTTPS connections
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Security-Auditing'
    Id = 5156
} | Where-Object {
    $_.Message -match ':8443'
}
```

## SIEM Rules

### Sigma Rule: RFC 5737 Detection

```yaml
title: DNS Response with RFC 5737 Documentation IP
id: a1b2c3d4-e5f6-7890-joker-rfc5737
status: experimental
description: Detects DNS responses containing RFC 5737 documentation IPs
author: Security Research
references:
    - https://github.com/faanross/joker_screenmate
logsource:
    category: dns
detection:
    selection:
        answer|re: '(198\.51\.100\.|203\.0\.113\.)\d+'
    condition: selection
falsepositives:
    - Development/test environments using documentation ranges
level: high
tags:
    - attack.command_and_control
    - attack.t1071.004
```

### Sigma Rule: TXT Burst

```yaml
title: DNS TXT Query Burst
id: b2c3d4e5-f6a7-8901-joker-txtburst
status: experimental
description: Detects burst of TXT queries indicating payload transfer
logsource:
    category: dns
detection:
    selection:
        qtype: TXT
    timeframe: 1m
    condition: selection | count() > 10
level: medium
tags:
    - attack.exfiltration
    - attack.t1048.003
```

## IOC Summary

### Network Indicators

| Indicator | Type | Confidence |
|-----------|------|------------|
| 198.51.100.0/24 in DNS | IP Range | High |
| 203.0.113.0/24 in DNS | IP Range | High |
| TXT query to "verify.*" | DNS Pattern | High |
| Base64 with 8-digit prefix | TXT Content | High |
| HTTPS POST to :8443/upload | HTTP Pattern | Medium |

### Behavioral Indicators

| Indicator | Description |
|-----------|-------------|
| 3-7 minute beacon interval | Jittered DNS queries |
| TXT burst (10+ queries) | Payload transfer |
| DNS→HTTPS within 5 min | Exfiltration sequence |

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| DNS | T1071.004 | C2 via DNS protocol |
| Data Transfer Size Limits | T1030 | Chunked TXT transfer |
| Exfiltration Over C2 | T1041 | HTTPS file upload |
| Application Layer Protocol | T1071 | DNS and HTTPS abuse |

## Hunting Workflow

### Step 1: Query for RFC 5737 Ranges

```
Search DNS logs for 198.51.100.x or 203.0.113.x
→ High confidence indicator
→ Investigate source hosts immediately
```

### Step 2: Analyze TXT Query Patterns

```
Look for TXT query bursts > 10/minute
→ Check if queries go to "verify.*"
→ Examine TXT response content for Base64
```

### Step 3: Correlate DNS and HTTPS

```
Find DNS queries followed by HTTPS within 5 minutes
→ Check HTTPS destination matches DNS query domain
→ Look for POST /upload patterns
```

### Step 4: Timeline Analysis

```
For suspected hosts:
→ Build 24-hour DNS timeline
→ Identify beacon intervals (expect 3-7 min)
→ Mark TXT bursts and HTTPS connections
```

## Next Steps

- [Architecture](architecture.md) - System design
- [Protocol](protocol.md) - Protocol specification
- [Server Guide](server-guide.md) - Server operation
