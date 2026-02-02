// check_google_group_permissions analyzes Google Groups to determine their permission
// settings and identify which groups are publicly accessible. This tool is useful for
// security assessments to find groups with overly permissive settings.
//
// The tool reads Google Groups URLs from stdin and checks each group's /about page
// to determine:
//   - Whether the group is public (accessible without authentication)
//   - Whether anyone can view conversations
//   - Whether anyone can post messages
//   - Whether anyone can join the group
//
// Usage:
//
//	cat urls.txt | ./check_google_group_permissions                  # find public groups
//	cat urls.txt | ./check_google_group_permissions -verbose         # show all permission details
//	cat urls.txt | ./check_google_group_permissions -require-post    # only groups where anyone can post
//
// Output:
//   - stdout: URLs of groups matching the criteria (public and accessible)
//   - stderr: Error messages, rejected groups, and verbose permission details
//
// Rate limiting: The tool makes at most 5 requests per second to avoid being blocked.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	// rateLimit controls the request frequency (5 requests per second).
	rateLimit = time.Second / 5
	// timeout is the maximum time to wait for an HTTP response.
	timeout = 10 * time.Second
)

// GroupPermissions represents the permission settings discovered for a Google Group.
type GroupPermissions struct {
	IsPublic    bool // True if the group is publicly accessible without login
	CanView     bool // True if "Anyone on the web" can view conversations
	CanPost     bool // True if "Anyone on the web" can post messages
	CanJoin     bool // True if "Anyone on the web" can join the group
	RequireAuth bool // True if the group requires authentication to access
}

// checkGroupHTML fetches and parses a Google Group's /about page to extract
// permission settings. It normalizes the URL to the /about page format and
// uses regex patterns to detect permission strings in the HTML response.
func checkGroupHTML(url string, client *http.Client) (*GroupPermissions, error) {
	// Parse and normalize URL to the about page format
	// Extract domain and group name, then reconstruct as /about URL
	pattern := regexp.MustCompile(`https?://groups\.google\.com/a/([^/]+)/g/([^/?#]+)`)
	matches := pattern.FindStringSubmatch(url)
	if len(matches) < 3 {
		return nil, fmt.Errorf("invalid Google Groups URL format")
	}
	
	domain := matches[1]
	groupName := matches[2]
	normalizedURL := fmt.Sprintf("https://groups.google.com/a/%s/g/%s/about", domain, groupName)

	req, err := http.NewRequest("GET", normalizedURL, nil)
	if err != nil {
		return nil, err
	}

	// Set a realistic User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check if redirected to login
	if resp.StatusCode == 302 || resp.StatusCode == 401 || resp.StatusCode == 403 {
		return &GroupPermissions{IsPublic: false, RequireAuth: true}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	html := string(body)
	perms := &GroupPermissions{IsPublic: true}

	// Use regex to match "Anyone on the web" followed by permission text
	// Limit the match to avoid crossing into other permission statements
	canViewPattern := regexp.MustCompile(`Anyone on the web.{0,50}?can view conversations`)
	canJoinPattern := regexp.MustCompile(`Anyone on the web.{0,50}?can join group`)
	canPostPattern := regexp.MustCompile(`Anyone on the web.{0,50}?can post`)

	perms.CanView = canViewPattern.MatchString(html)
	perms.CanJoin = canJoinPattern.MatchString(html)
	perms.CanPost = canPostPattern.MatchString(html)

	return perms, nil
}

// extractGroupEmail extracts the group email address from a Google Groups URL.
// For example, the URL "https://groups.google.com/a/list.nist.gov/g/internet-time-service"
// returns "internet-time-service@list.nist.gov".
func extractGroupEmail(url string) string {
	// Extract domain and group name from URL.
	pattern := regexp.MustCompile(`https?://groups\.google\.com/a/([^/]+)/g/([^/?#]+)`)
	matches := pattern.FindStringSubmatch(url)
	if len(matches) > 2 {
		domain := matches[1]
		groupName := matches[2]
		return fmt.Sprintf("%s@%s", groupName, domain)
	}
	return ""
}

func main() {
	verbose := flag.Bool("verbose", false, "Show detailed permission information for all groups")
	requirePost := flag.Bool("require-post", false, "Only output groups where anyone can post")
	flag.Parse()

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Check if redirecting to login
			if strings.Contains(req.URL.String(), "accounts.google.com") {
				return http.ErrUseLastResponse
			}
			// Allow other redirects (up to 10)
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	scanner := bufio.NewScanner(os.Stdin)
	ticker := time.NewTicker(rateLimit)
	defer ticker.Stop()

	for scanner.Scan() {
		url := scanner.Text()

		groupEmail := extractGroupEmail(url)
		if groupEmail == "" {
			fmt.Fprintf(os.Stderr, "Could not extract group email from %s\n", url)
			continue
		}

		// Wait for rate limit
		<-ticker.C

		perms, err := checkGroupHTML(url, client)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error checking %s: %v\n", url, err)
			continue
		}

		// Determine if group is "open" based on criteria
		isOpen := perms.IsPublic && (perms.CanView || perms.CanJoin)
		if *requirePost {
			isOpen = isOpen && perms.CanPost
		}

		if *verbose {
			fmt.Fprintf(os.Stderr, "Group: %s | Public: %v | View: %v | Post: %v | Join: %v | RequireAuth: %v\n",
				groupEmail, perms.IsPublic, perms.CanView, perms.CanPost, perms.CanJoin, perms.RequireAuth)
		} else if !isOpen {
			fmt.Fprintf(os.Stderr, "Rejected %s (not publicly accessible)\n", groupEmail)
		}

		if isOpen {
			fmt.Println(url)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}
