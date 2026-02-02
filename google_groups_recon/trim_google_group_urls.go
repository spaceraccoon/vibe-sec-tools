// trim_google_group_urls normalizes and deduplicates Google Workspace group URLs.
// It validates that URLs match the expected Google Groups pattern and removes
// duplicate entries.
//
// The tool supports two modes of operation:
//
// Without -trim flag: Deduplicates full URLs while preserving query parameters
// and fragments.
//
// With -trim flag: Extracts and deduplicates base URLs, removing anything after
// the group name (query strings, fragments, subpaths).
//
// Usage:
//
//	cat urls.txt | ./trim_google_group_urls         # deduplicate full URLs
//	cat urls.txt | ./trim_google_group_urls -trim   # normalize to base URLs
//
// Example input:
//
//	https://groups.google.com/a/example.com/g/team/c/abc123
//	https://groups.google.com/a/example.com/g/team?hl=en
//	https://groups.google.com/a/example.com/g/team
//
// Example output (with -trim):
//
//	https://groups.google.com/a/example.com/g/team
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
)

func main() {
	trim := flag.Bool("trim", false, "Trim URLs to base group URL format and deduplicate")
	flag.Parse()

	// Pattern for Google Workspace groups with custom domains.
	// Example: https://groups.google.com/a/list.nist.gov/g/internet-time-service
	pattern := regexp.MustCompile(`https?://groups\.google\.com/a/[^/]+/g/[^/]+`)

	scanner := bufio.NewScanner(os.Stdin)
	seen := make(map[string]bool)
	
	for scanner.Scan() {
		url := scanner.Text()
		
		if *trim {
			// Extract and trim to base URL
			match := pattern.FindString(url)
			if match != "" && !seen[match] {
				seen[match] = true
				fmt.Println(match)
			}
		} else {
			// Original behavior: match full URL
			if pattern.MatchString(url) && !seen[url] {
				seen[url] = true
				fmt.Println(url)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}
