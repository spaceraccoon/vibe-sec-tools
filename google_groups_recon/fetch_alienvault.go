// fetch_alienvault fetches historical URLs associated with a domain from AlienVault's
// Open Threat Exchange (OTX) API. This tool is useful for discovering URLs that have
// been historically observed for a given domain, which can then be processed by other
// tools in this reconnaissance pipeline.
//
// Usage:
//
//	./fetch_alienvault -domain groups.google.com
//
// The tool queries the AlienVault OTX API with pagination support, handling rate
// limits automatically (max 10,000 requests per hour). URLs are output to stdout
// one per line, while status messages and errors go to stderr.
//
// Example pipeline:
//
//	./fetch_alienvault -domain groups.google.com | ./trim_google_group_urls -trim > urls.txt
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// baseURL is the AlienVault OTX API endpoint for fetching URL lists by hostname.
	baseURL = "https://otx.alienvault.com/otxapi/indicators/hostname/url_list"
	// limitPerPage defines how many results to request per API call.
	limitPerPage = 100
	// requestsPerHour is set slightly below the API limit (10,000) to provide a safety margin.
	requestsPerHour = 9500
)

// Response represents the JSON response structure from the AlienVault OTX API.
type Response struct {
	HasNext    bool      `json:"has_next"`
	ActualSize int       `json:"actual_size"`
	URLList    []URLInfo `json:"url_list"`
}

// URLInfo represents a single URL entry from the AlienVault response.
type URLInfo struct {
	URL      string `json:"url"`      // The full URL that was observed
	Domain   string `json:"domain"`   // The domain portion of the URL
	Hostname string `json:"hostname"` // The hostname portion of the URL
	HTTPCode int    `json:"httpcode"` // HTTP status code when URL was observed
	Date     string `json:"date"`     // Date when the URL was observed
}

// fetchURLs retrieves a single page of URL results from the AlienVault OTX API.
// Returns an error if the request fails or if rate limits are exceeded.
func fetchURLs(domain string, page int) (*Response, error) {
	url := fmt.Sprintf("%s/%s?limit=%d&page=%d", baseURL, domain, limitPerPage, page)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &response, nil
}

func main() {
	domain := flag.String("domain", "", "Domain to query (required)")
	flag.Parse()

	if *domain == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -domain <domain>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -domain groups.google.com\n", os.Args[0])
		os.Exit(1)
	}

	page := 1
	count := 0
	startTime := time.Now()

	for {
		// Check if we need to wait for the hourly limit to reset
		if count > 0 && count%requestsPerHour == 0 {
			elapsed := time.Since(startTime)
			if elapsed < time.Hour {
				waitTime := time.Hour - elapsed
				fmt.Fprintf(os.Stderr, "Reached hourly limit (%d requests). Waiting %v before continuing...\n", requestsPerHour, waitTime)
				time.Sleep(waitTime)
				startTime = time.Now()
			} else {
				startTime = time.Now()
			}
		}

		response, err := fetchURLs(*domain, page)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching page %d: %v\n", page, err)
			os.Exit(1)
		}

		// Output URLs to stdout
		for _, urlInfo := range response.URLList {
			fmt.Println(urlInfo.URL)
			count++
		}

		// Check if there are more pages
		if !response.HasNext {
			break
		}

		page++
	}

	fmt.Fprintf(os.Stderr, "Completed fetching %d URLs for domain: %s\n", count, *domain)
}
