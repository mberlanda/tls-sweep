package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

var logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)

const ianaTLDListURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
const cacheDir = ".cache"

var cacheFile = fmt.Sprintf("%s/tlds.cache", cacheDir)
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

	forceRefresh := false
	if len(os.Args) > 2 && os.Args[2] == "--force-tld-refresh" {
		forceRefresh = true
	}

	var tlds, err = loadTLDs(!forceRefresh)
	if err != nil {
		logger.Fatalf("Failed to load TLDs: %v\n", err)
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

	exportToCsv(baseDomain, results)
}

func exportToCsv(baseDomain string, results chan ScanResult) {
	fileName := fmt.Sprintf("%s.csv", baseDomain)
	file, err := os.Create(fileName)
	if err != nil {
		logger.Printf("Failed to create file: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Domain", "IP", "Status", "Subject", "Issuer", "ValidTo"})

	var DomainsNotFound []string
	for res := range results {
		if res.Status == "NXDOMAIN" {
			// After changing the logger implementation, this line may be a debug log
			// logger.Printf("Domain %s does not exist\n", res.Domain)
			DomainsNotFound = append(DomainsNotFound, res.Domain)
			continue // skip non-existent domains
		}
		writer.Write([]string{res.Domain, res.IP, res.Status, res.Subject, res.Issuer, res.ValidTo})
	}

	logger.Printf("Found %d domains that do not exist: ", len(DomainsNotFound))
	logger.Printf("Domains not found: ", strings.Join(DomainsNotFound, ", "))

	logger.Printf("Results exported to %s\n", fileName)
}

func loadTLDs(useCache bool) ([]string, error) {
	const cache_sep = "\t"

	var tlds []string
	var err error

	if useCache {
		if _, err := os.Stat(cacheFile); err == nil {
			logger.Println("Loading TLDs from cache...")
			file, err := os.Open(cacheFile)
			if err == nil {
				defer file.Close()
				content, _ := io.ReadAll(file)
				tlds = strings.Split(string(content), cache_sep)
				if len(tlds) > 0 {
					logger.Println("TLDs loaded from cache.")
				}
			}
		}
	}

	if len(tlds) == 0 {
		logger.Println("Fetching TLDs from IANA...")
		tlds, err = fetchTLDs()
		if err != nil {
			return nil, err
		}

		if err := os.MkdirAll(cacheDir, os.ModePerm); err == nil {
			file, err := os.Create(cacheFile)
			if err == nil {
				defer file.Close()
				file.WriteString(strings.Join(tlds, cache_sep))
				logger.Println("TLDs cached.")
			}
		}
	}
	return tlds, err
}

func fetchTLDs() ([]string, error) {
	var tlds []string

	resp, err := http.Get(ianaTLDListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch TLDs: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines[1:] {
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
