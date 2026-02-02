# Google Groups Reconnaissance Tools

A suite of Go tools for discovering and analyzing publicly accessible Google Workspace groups. These tools help security professionals identify groups with overly permissive settings during authorized security assessments.

## Overview

Google Workspace allows organizations to host Google Groups on custom domains (e.g., `groups.google.com/a/example.com/g/team`). Misconfigured groups can expose sensitive information or allow unauthorized posting. This toolset helps identify such groups through passive reconnaissance.

## Tools

### fetch_alienvault

Fetches historical URLs from AlienVault's Open Threat Exchange (OTX) API for a given domain.

```bash
./fetch_alienvault -domain groups.google.com > urls.txt
```

**Features:**
- Pagination support for large result sets
- Automatic rate limit handling (max 10,000 requests/hour)
- Outputs URLs to stdout, status messages to stderr

### filter_google_group_domains

Extracts unique custom domains from Google Workspace group URLs.

```bash
cat urls.txt | ./filter_google_group_domains > domains.txt
```

**Input:** Google Groups URLs (one per line)
**Output:** Unique domain names (e.g., `list.nist.gov`, `example.com`)

### trim_google_group_urls

Normalizes and deduplicates Google Groups URLs.

```bash
cat urls.txt | ./trim_google_group_urls -trim > normalized_urls.txt
```

**Flags:**
- `-trim`: Remove query strings, fragments, and subpaths; output base URLs only

**Without `-trim`:** Deduplicates while preserving full URLs
**With `-trim`:** Normalizes to base format (`https://groups.google.com/a/{domain}/g/{group}`)

### check_google_group_permissions

Analyzes permission settings for Google Groups to find publicly accessible ones.

```bash
cat normalized_urls.txt | ./check_google_group_permissions > open_groups.txt
```

**Flags:**
- `-verbose`: Show detailed permission info for all groups (to stderr)
- `-require-post`: Only output groups where anyone can post

**Output:**
- stdout: URLs of publicly accessible groups
- stderr: Errors, rejected groups, and verbose details

**Rate limiting:** 5 requests per second

## Typical Workflow

```bash
# Step 1: Fetch historical URLs from AlienVault
./fetch_alienvault -domain groups.google.com > all_urls.txt

# Step 2: Normalize and deduplicate
cat all_urls.txt | ./trim_google_group_urls -trim > normalized_urls.txt

# Step 3: (Optional) Extract unique domains for analysis
cat normalized_urls.txt | ./filter_google_group_domains > domains.txt

# Step 4: Find publicly accessible groups
cat normalized_urls.txt | ./check_google_group_permissions > open_groups.txt

# Step 5: Find groups where anyone can post (higher risk)
cat normalized_urls.txt | ./check_google_group_permissions -require-post > posting_groups.txt
```

## Building

Each tool is a standalone Go program with no external dependencies:

```bash
cd google_groups_recon
go build -o fetch_alienvault fetch_alienvault.go
go build -o filter_google_group_domains filter_google_group_domains.go
go build -o trim_google_group_urls trim_google_group_urls.go
go build -o check_google_group_permissions check_google_group_permissions.go
```

Or build all at once:

```bash
go build ./...
```

## Permission Levels Detected

The `check_google_group_permissions` tool identifies these permission settings:

| Permission | Description | Risk Level |
|------------|-------------|------------|
| Public View | Anyone on the web can view conversations | Medium |
| Public Join | Anyone on the web can join the group | Medium |
| Public Post | Anyone on the web can post messages | High |

A group is considered "open" if it's public AND allows viewing OR joining.

## Dependencies

- Go 1.16 or later
- Standard library only (no external packages)

## License

See the repository's main LICENSE file.
