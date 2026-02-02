// filter_google_group_domains extracts unique custom domains from Google Workspace
// group URLs. This tool reads URLs from stdin and outputs deduplicated domain names
// to stdout.
//
// Google Workspace groups use URLs in the format:
//
//	https://groups.google.com/a/{domain}/g/{group-name}
//
// This tool extracts the {domain} portion (e.g., "list.nist.gov") from each URL.
//
// Usage:
//
//	cat urls.txt | ./filter_google_group_domains
//
// Example input:
//
//	https://groups.google.com/a/list.nist.gov/g/internet-time-service
//	https://groups.google.com/a/example.com/g/announcements
//
// Example output:
//
//	list.nist.gov
//	example.com
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

func main() {
	// Pattern to extract custom domain from Google Workspace group URLs.
	// Example: https://groups.google.com/a/list.nist.gov/g/internet-time-service
	// Captures: list.nist.gov
	pattern := regexp.MustCompile(`https?://groups\.google\.com/a/([^/]+)/g/`)

	scanner := bufio.NewScanner(os.Stdin)
	seen := make(map[string]bool)

	for scanner.Scan() {
		url := scanner.Text()

		matches := pattern.FindStringSubmatch(url)
		if len(matches) > 1 {
			domain := matches[1]
			if !seen[domain] {
				seen[domain] = true
				fmt.Println(domain)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}
