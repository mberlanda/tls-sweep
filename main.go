package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const ianaTLDListURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

var maxWorkers = 2 * runtime.NumCPU()

type ScanResult struct {
	Domain  string
	IP      string
	Status  string
	Subject string
	Issuer  string
	ValidTo string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run tls_sweep.go <base-domain>")
		os.Exit(1)
	}
	baseDomain := os.Args[1]

	tlds, err := fetchTLDs()
	if err != nil {
		panic(err)
	}

	tasks := make(chan string, len(tlds))
	results := make(chan ScanResult, len(tlds))

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go worker(tasks, results, &wg)
	}

	for _, tld := range tlds {
		if strings.HasPrefix(tld, "xn--") {
			continue // skip IDNs
		}
		domain := fmt.Sprintf("%s.%s", baseDomain, tld)
		tasks <- domain
	}
	close(tasks)

	wg.Wait()
	close(results)

	fmt.Printf("| %-30s | %-15s | %-10s | %-30s |\n", "Domain", "IP", "Status", "Subject")
	fmt.Println(strings.Repeat("-", 100))

	for res := range results {
		fmt.Printf("| %-30s | %-15s | %-10s | %-30s |\n", res.Domain, res.IP, res.Status, res.Subject)
	}
}

func fetchTLDs() ([]string, error) {
	resp, err := http.Get(ianaTLDListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TLDs: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	var tlds []string
	for _, line := range lines[1:] { // skip first line
		tld := strings.ToLower(strings.TrimSpace(line))
		if len(tld) > 0 {
			tlds = append(tlds, tld)
		}
	}
	return tlds, nil
}

func worker(tasks <-chan string, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range tasks {
		result := scanDomain(domain)
		results <- result
	}
}

func scanDomain(domain string) ScanResult {
	ips, err := net.LookupHost(domain)
	if err != nil || len(ips) == 0 {
		return ScanResult{Domain: domain, IP: "-", Status: "NXDOMAIN"}
	}
	ip := ips[0]

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return ScanResult{Domain: domain, IP: ip, Status: "TLS ERROR"}
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ScanResult{Domain: domain, IP: ip, Status: "NO CERT"}
	}
	cert := state.PeerCertificates[0]

	return ScanResult{
		Domain:  domain,
		IP:      ip,
		Status:  "OK",
		Subject: certSubject(cert),
		Issuer:  cert.Issuer.CommonName,
		ValidTo: cert.NotAfter.Format("2006-01-02"),
	}
}

func certSubject(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return "(no subject)"
}
