# vibe-sec-tools

A collection of (mostly) vibe-coded security tools for penetration testing and security research.

## Tools

### [google_groups_recon](google_groups_recon/)

A suite of Go tools for discovering and analyzing publicly accessible Google Workspace groups. Helps identify groups with overly permissive settings (public viewing, posting, or joining) that could expose sensitive information.

**Tools included:**
- `fetch_alienvault` - Fetch historical URLs from AlienVault OTX API
- `filter_google_group_domains` - Extract unique domains from Google Groups URLs
- `trim_google_group_urls` - Normalize and deduplicate Google Groups URLs
- `check_google_group_permissions` - Analyze permission settings for public accessibility

## License

See [LICENSE](LICENSE) for details.
