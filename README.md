# Chrome Curl

This simple Claude written app connects to a chrome application via the
debugger port to attempt to download content to a local file.

```
Usage: go run main.go <URL> [output_destination]
Examples:
  go run main.go https://example.com                    # Save to output.html
  go run main.go https://example.com output.html        # Save to specific file
  go run main.go https://example.com -                  # Output to stdout
  go run main.go https://example.com ./cache/           # Save to folder with URL hash name
  go run main.go https://example.com /tmp/scraped       # Save to folder with URL hash name

Environment Variables:
  CHROME_HOST      - Chrome host (default: localhost)
  CHROME_PORT      - Chrome port (default: 9222)
  LOG_LEVEL        - Log level: debug, info, warn, error (default: info)
  LOG_PRETTY       - Pretty print logs: true/false (default: false)

Output Detection:
  [filename.ext]   - Detected as file output
  -                - Detected as stdout output
  [path/to/dir]    - Detected as folder output (saves as [first 2 chars of SHA1]/[SHA1_HASH_OF_URL])
  [path/to/dir/]   - Detected as folder output (trailing slash)

Folder detection criteria:
  • Existing directory
  • Path ending with / or \
  • Path with no file extension
  • Path containing common directory names (cache, output, data, etc.)

Make sure Chrome is running with remote debugging enabled:
google-chrome --disable-http2 --remote-debugging-port=9222 --remote-allow-origins=*
```
