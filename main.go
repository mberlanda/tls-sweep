package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run tls_sweep.go <base-domain>")
		os.Exit(1)
	}
	baseDomain := os.Args[1]
	fmt.Println("Starting TLS sweep for domain:", baseDomain)
}
