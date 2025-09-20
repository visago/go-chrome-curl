package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	_ "github.com/sanity-io/litter"
)

// Configuration structure
type Config struct {
	ChromeHost   string
	ChromePort   string
	LogLevel     string
	OutputFolder string
	Retries      int
}

var try int

func loadConfig() *Config {
	config := &Config{
		ChromeHost:   getEnv("CHROME_HOST", "localhost"),
		ChromePort:   getEnv("CHROME_PORT", "9222"),
		LogLevel:     getEnv("LOG_LEVEL", "warn"),
		Retries:      getEnvInt("RETRIES", 3),
		OutputFolder: "",
	}
	return config
}

func getEnv(key string, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		integer, err := strconv.Atoi(value)
		if err != nil {
			return defaultValue
		} else {
			return integer
		}
	}
	return defaultValue
}

func setupLogging(level string) {
	// Configure zerolog
	zerolog.TimeFieldFormat = time.RFC3339

	// Set log level
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Pretty print for development
	if os.Getenv("LOG_PRETTY") == "true" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}

// Check if path is a folder or could be a folder path
func isOrCouldBeFolder(path string) bool {
	if path == "" || path == "-" {
		return false
	}

	// Check if it exists and is a directory
	if info, err := os.Stat(path); err == nil {
		return info.IsDir()
	}

	// If it doesn't exist, check if it looks like a folder path
	// (ends with / or doesn't have a file extension)
	if strings.HasSuffix(path, "/") || strings.HasSuffix(path, "\\") {
		return true
	}

	// Check if it has no extension (likely a folder)
	if filepath.Ext(path) == "" {
		return true
	}

	// If it has common directory names
	base := filepath.Base(path)
	commonDirNames := []string{"cache", "output", "data", "files", "downloads", "temp", "tmp"}
	for _, dirName := range commonDirNames {
		if strings.Contains(strings.ToLower(base), dirName) {
			return true
		}
	}

	return false
}

// Determine output mode based on second argument
func determineOutputMode(arg2 string) (outputMode string, outputPath string) {
	if arg2 == "" {
		return "file", "output.html"
	}

	if arg2 == "-" {
		return "stdout", ""
	}

	if isOrCouldBeFolder(arg2) {
		return "folder", arg2
	}

	return "file", arg2
}

// Generate SHA1 hash of URL in uppercase
func generateURLHash(url string) string {
	hash := sha1.Sum([]byte(url))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}

// Check if directory exists and is writable, create if it doesn't exist
func validateOutputFolder(folderPath string) error {
	if folderPath == "" {
		return nil // No folder specified, skip validation
	}

	// Check if folder exists
	info, err := os.Stat(folderPath)
	if os.IsNotExist(err) {
		log.Debug().Str("folder", folderPath).Msg("Output folder doesn't exist, creating it")
		if err := os.MkdirAll(folderPath, 0755); err != nil {
			log.Error().Err(err).Str("folder", folderPath).Msg("Failed to create output folder")
			return fmt.Errorf("failed to create output folder: %v", err)
		}
		log.Info().Str("folder", folderPath).Msg("Output folder created successfully")
		return nil
	}

	if err != nil {
		log.Error().Err(err).Str("folder", folderPath).Msg("Failed to stat output folder")
		return fmt.Errorf("failed to stat output folder: %v", err)
	}

	if !info.IsDir() {
		log.Error().Str("path", folderPath).Msg("Output path exists but is not a directory")
		return fmt.Errorf("output path is not a directory: %s", folderPath)
	}

	// Test write permission by creating a temporary file
	testFile := filepath.Join(folderPath, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		log.Error().Err(err).Str("folder", folderPath).Msg("Output folder is not writable")
		return fmt.Errorf("output folder is not writable: %v", err)
	}
	os.Remove(testFile) // Clean up test file

	log.Debug().Str("folder", folderPath).Msg("Output folder validated successfully")
	return nil
}

// Write content to appropriate destination
func writeContent(content, targetURL, outputMode, outputPath string) error {
	switch outputMode {
	case "folder":
		// Write to folder with URL hash filename
		urlHash := generateURLHash(targetURL)
		firstTwo := urlHash[:2]
		outputPath = filepath.Join(outputPath, firstTwo)
		if err := validateOutputFolder(outputPath); err != nil {
			log.Fatal().Err(err).Msgf("Invalid output folder %s", outputPath)
		}
		hashFilename := urlHash
		hashFilePath := filepath.Join(outputPath, hashFilename)

		log.Debug().
			Str("folder", outputPath).
			Str("url", targetURL).
			Str("hash", urlHash).
			Str("filename", hashFilename).
			Msg("Writing content to hash-named file in output folder")

		if err := os.WriteFile(hashFilePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("error writing to hash file: %v", err)
		}

		log.Warn().
			Int("try", try).
			Str("url", targetURL).
			Str("folder", outputPath).
			Str("file", hashFilePath).
			Int("content_length", len(content)).
			Msg("Successfully saved website content to hash-named file")

	case "stdout":
		log.Debug().Msg("Writing content to stdout")
		fmt.Print(content)
		log.Warn().
			Int("try", try).
			Str("url", targetURL).
			Int("content_length", len(content)).
			Msg("Successfully output website content to stdout")

	case "file":
		log.Debug().Str("file", outputPath).Msg("Writing content to file")
		if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("error writing to file: %v", err)
		}

		log.Warn().
			Int("try", try).
			Str("url", targetURL).
			Str("file", outputPath).
			Int("content_length", len(content)).
			Msg("Successfully saved website content")

	default:
		return fmt.Errorf("unknown output mode: %s", outputMode)
	}

	return nil
}

type TabInfo struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Type         string `json:"type"`
	URL          string `json:"url"`
	WebSocketURL string `json:"webSocketDebuggerUrl"`
}

type CDPMessage struct {
	ID     int         `json:"id"`
	Method string      `json:"method"`
	Params interface{} `json:"params,omitempty"`
}

type CDPResponse struct {
	ID     int                    `json:"id"`
	Result map[string]interface{} `json:"result"`
	Error  interface{}            `json:"error,omitempty"`
}

type ChromeDebugger struct {
	conn   *websocket.Conn
	msgID  int
	config *Config
}

func NewChromeDebugger(config *Config) *ChromeDebugger {
	return &ChromeDebugger{
		config: config,
	}
}

// Get list of available tabs from Chrome
func (cd *ChromeDebugger) getTabs() ([]TabInfo, error) {
	url := fmt.Sprintf("http://%s:%s/json", cd.config.ChromeHost, cd.config.ChromePort)
	log.Debug().Str("url", url).Msg("Fetching Chrome tabs")

	resp, err := http.Get(url)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get tabs from Chrome")
		return nil, fmt.Errorf("failed to get tabs: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body")
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var tabs []TabInfo
	if err := json.Unmarshal(body, &tabs); err != nil {
		log.Error().Err(err).Str("body", string(body)).Msg("Failed to parse tabs JSON")
		return nil, fmt.Errorf("failed to parse tabs JSON: %v", err)
	}

	log.Debug().Int("tab_count", len(tabs)).Msg("Retrieved Chrome tabs")
	return tabs, nil
}

// Connect to a Chrome tab via WebSocket
func (cd *ChromeDebugger) connectToTab(wsURL string) error {
	log.Debug().Str("websocket_url", wsURL).Msg("Connecting to Chrome tab")

	var err error
	cd.conn, _, err = websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Error().Err(err).Str("websocket_url", wsURL).Msg("Failed to connect to WebSocket")
		return fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	log.Debug().Msg("Successfully connected to Chrome tab")
	return nil
}

// Send a CDP message and wait for response
func (cd *ChromeDebugger) sendMessage(method string, params interface{}) (map[string]interface{}, error) {
	cd.msgID++
	msg := CDPMessage{
		ID:     cd.msgID,
		Method: method,
		Params: params,
	}

	log.Debug().
		Int("try", try).
		Int("message_id", cd.msgID).
		Str("method", method).
		Interface("params", params).
		Msg("Sending CDP message")

	if err := cd.conn.WriteJSON(msg); err != nil {
		log.Error().Err(err).Str("method", method).Msg("Failed to send CDP message")
		return nil, fmt.Errorf("failed to send message: %v", err)
	}

	// Read response
	for {
		var response CDPResponse
		if err := cd.conn.ReadJSON(&response); err != nil {
			log.Error().Int("try", try).Err(err).Msg("Failed to read CDP response")
			return nil, fmt.Errorf("failed to read response: %v", err)
		}

		log.Debug().
			Int("try", try).
			Int("response_id", response.ID).
			Int("expected_id", cd.msgID).
			Interface("error", response.Error).
			Msg("Received CDP response")

		// Check if this is the response to our message
		if response.ID == cd.msgID {
			if response.Error != nil {
				log.Error().Int("try", try).Interface("error", response.Error).Str("method", method).Msg("CDP method returned error")
				return nil, fmt.Errorf("CDP error: %v", response.Error)
			}
			log.Debug().Int("try", try).Str("method", method).Msg("CDP method executed successfully")
			return response.Result, nil
		}
		// Otherwise, it might be an event or response to another message, continue reading
	}
}

// Navigate to a URL
func (cd *ChromeDebugger) navigateTo(url string) error {
	log.Info().Str("url", url).Msg("Navigating to URL")
	params := map[string]string{"url": url}
	_, err := cd.sendMessage("Page.navigate", params)
	if err != nil {
		log.Error().Int("try", try).Err(err).Str("url", url).Msg("Failed to navigate to URL")
	}
	return err
}

// Wait for page to load and get response info
func (cd *ChromeDebugger) waitForLoadAndGetResponse(timeout time.Duration) (int, error) {
	log.Info().Int("try", try).Dur("timeout", timeout).Msg("Waiting for page to load")

	// Enable page domain events
	if _, err := cd.sendMessage("Page.enable", nil); err != nil {
		log.Error().Int("try", try).Err(err).Msg("Failed to enable Page domain")
		return 0, err
	}

	// Enable network domain to capture response
	if _, err := cd.sendMessage("Network.enable", nil); err != nil {
		log.Error().Int("try", try).Err(err).Msg("Failed to enable Network domain")
		return 0, err
	}

	var httpStatusCode int
	loadComplete := false
	done := make(chan struct{})
	var resultErr error

	// Start a goroutine to read WebSocket messages
	go func() {
		defer close(done)
		for {
			var event map[string]interface{}
			if err := cd.conn.ReadJSON(&event); err != nil {
				log.Error().Int("try", try).Err(err).Msg("Failed to read page load event")
				resultErr = fmt.Errorf("failed to read event: %v", err)
				return
			}

			if method, ok := event["method"].(string); ok {
				log.Debug().Int("try", try).Str("event_method", method).Msg("Received page event")
				switch method {
				case "Network.responseReceived":
					if params, ok := event["params"].(map[string]interface{}); ok {
						if response, ok := params["response"].(map[string]interface{}); ok {
							if status, ok := response["status"].(float64); ok {
								if httpStatusCode == 0 { // Only capture the first response (main document)
									httpStatusCode = int(status)
									log.Info().Int("try", try).Int("http_status", httpStatusCode).Msg("Received HTTP response")
								}
							}
						}
					}
				case "Page.loadEventFired":
					loadComplete = true
					log.Info().Int("try", try).Msg("Page load completed")
				}

				// If we have both status code and load completion, we're done
				if loadComplete && httpStatusCode != 0 {
					return
				}
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		if resultErr != nil {
			return 0, resultErr
		}
		if loadComplete && httpStatusCode != 0 {
			return httpStatusCode, nil
		}
		return 0, fmt.Errorf("page load completed but missing status code or load event")
	case <-time.After(timeout):
		log.Error().Int("try", try).Dur("timeout", timeout).Int("http_status", httpStatusCode).Bool("load_complete", loadComplete).Msg("Timeout waiting for page load")
		return 0, fmt.Errorf("timeout waiting for page load after %v", timeout)
	}
}

// Get page content (HTML)
func (cd *ChromeDebugger) getPageContent() (string, error) {
	log.Debug().Int("try", try).Msg("Getting page content")

	// Enable DOM domain
	if _, err := cd.sendMessage("DOM.enable", nil); err != nil {
		log.Error().Int("try", try).Err(err).Msg("Failed to enable DOM domain")
		return "", err
	}

	// Get document
	docResult, err := cd.sendMessage("DOM.getDocument", nil)
	if err != nil {
		log.Error().Int("try", try).Err(err).Msg("Failed to get document")
		return "", err
	}

	// Get outer HTML
	params := map[string]interface{}{
		"nodeId": docResult["root"].(map[string]interface{})["nodeId"],
	}

	result, err := cd.sendMessage("DOM.getOuterHTML", params)
	if err != nil {
		log.Error().Int("try", try).Err(err).Msg("Failed to get outer HTML")
		return "", err
	}

	outerHTML, ok := result["outerHTML"].(string)
	if !ok {
		log.Error().Int("try", try).Msg("Failed to extract HTML content from result")
		return "", fmt.Errorf("failed to get HTML content")
	}

	log.Info().Int("try", try).Int("content_length", len(outerHTML)).Msg("Successfully extracted page content")
	return outerHTML, nil
}

// Close connection
func (cd *ChromeDebugger) close() {
	if cd.conn != nil {
		log.Debug().Msg("Closing Chrome debugger connection")
		cd.conn.Close()
	}
}

func main() {
	// Load configuration and setup logging
	config := loadConfig()
	setupLogging(config.LogLevel)

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <URL> [output_destination]")
		fmt.Println("Examples:")
		fmt.Println("  go run main.go https://example.com                    # Save to output.html")
		fmt.Println("  go run main.go https://example.com output.html        # Save to specific file")
		fmt.Println("  go run main.go https://example.com -                  # Output to stdout")
		fmt.Println("  go run main.go https://example.com ./cache/           # Save to folder with URL hash name")
		fmt.Println("  go run main.go https://example.com /tmp/scraped       # Save to folder with URL hash name")
		fmt.Println("\nEnvironment Variables:")
		fmt.Println("  CHROME_HOST      - Chrome host (default: localhost)")
		fmt.Println("  CHROME_PORT      - Chrome port (default: 9222)")
		fmt.Println("  LOG_LEVEL        - Log level: debug, info, warn, error (default: warn)")
		fmt.Println("  LOG_PRETTY       - Pretty print logs: true/false (default: false)")
		fmt.Println("  RETRIES       - Retries (default: 3)")
		fmt.Println("\nOutput Detection:")
		fmt.Println("  [filename.ext]   - Detected as file output")
		fmt.Println("  -                - Detected as stdout output")
		fmt.Println("  [path/to/dir]    - Detected as folder output (saves as [SHA1_HASH_OF_URL].html)")
		fmt.Println("  [path/to/dir/]   - Detected as folder output (trailing slash)")
		fmt.Println("\nFolder detection criteria:")
		fmt.Println("  • Existing directory")
		fmt.Println("  • Path ending with / or \\")
		fmt.Println("  • Path with no file extension")
		fmt.Println("  • Path containing common directory names (cache, output, data, etc.)")
		fmt.Println("\nHTTP Status Handling:")
		fmt.Println("  • Only HTTP 200/304 responses will be saved")
		fmt.Println("  • Non-200/304 responses will exit with error code 1")
		fmt.Println("  • HTTP status is logged for debugging")
		fmt.Println("\nMake sure Chrome is running with remote debugging enabled:")
		fmt.Printf("google-chrome --remote-debugging-port=%s\n", config.ChromePort)
		os.Exit(1)
	}

	targetURL := os.Args[1]
	var arg2 string
	if len(os.Args) > 2 {
		arg2 = os.Args[2]
	}

	// Determine output mode and path
	outputMode, outputPath := determineOutputMode(arg2)

	log.Debug().
		Str("target_url", targetURL).
		Str("output_mode", outputMode).
		Str("output_path", outputPath).
		Str("raw_arg", arg2).
		Msg("Starting Chrome debugger application")

	// Validate output folder if using folder mode
	if outputMode == "folder" {
		if err := validateOutputFolder(outputPath); err != nil {
			log.Fatal().Err(err).Msg("Invalid output folder")
		}
	}

	try = 1
	found := false

	for try <= config.Retries && !found {
		// Create debugger instance
		debugger := NewChromeDebugger(config)
		defer debugger.close()

		// Get available tabs
		log.Debug().Msg("Getting available Chrome tabs")
		tabs, err := debugger.getTabs()
		if err != nil {
			log.Fatal().Err(err).Msg("Error getting tabs")
		}

		if len(tabs) == 0 {
			log.Fatal().
				Str("chrome_host", config.ChromeHost).
				Str("chrome_port", config.ChromePort).
				Msg("No Chrome tabs found. Make sure Chrome is running with --remote-debugging-port")
		}

		// Use the first available tab
		var selectedTab TabInfo
		for _, tab := range tabs {
			if tab.Type == "page" && tab.WebSocketURL != "" {
				selectedTab = tab
				break
			}
		}

		if selectedTab.WebSocketURL == "" {
			log.Fatal().Msg("No suitable tab found")
		}

		log.Debug().
			Str("tab_title", selectedTab.Title).
			Str("tab_url", selectedTab.URL).
			Str("tab_id", selectedTab.ID).
			Msg("Using Chrome tab")

		// Connect to the tab
		if err := debugger.connectToTab(selectedTab.WebSocketURL); err != nil {
			log.Fatal().Err(err).Msg("Error connecting to tab")
		}

		// Navigate to target URL
		if err := debugger.navigateTo(targetURL); err != nil {
			log.Error().Int("try", try).Err(err).Msg("Error navigating to URL")
			try++
			continue
		}

		// Wait for page to load and get HTTP status
		log.Info().Int("try", try).Msg("Waiting for page to load and checking HTTP status")
		httpStatus, err := debugger.waitForLoadAndGetResponse(10 * time.Second)
		if err != nil {
			log.Error().Int("try", try).Err(err).Msg("Error waiting for page load")
			try++
			continue
		}

		log.Info().Int("try", try).Int("http_status", httpStatus).Msg("Page loaded with HTTP status")

		// Check if HTTP status is 200
		if httpStatus != 200 && httpStatus != 304 {
			log.Error().
				Int("try", try).
				Int("http_status", httpStatus).
				Str("url", targetURL).
				Msg("HTTP status is not 200/304, skipping content extraction")
			try++
			continue
		}

		// Get page content
		content, err := debugger.getPageContent()
		if err != nil {
			log.Error().Int("try", try).Err(err).Msg("Error getting page content")
			try++
			continue
		}

		// Write content based on determined mode
		if err := writeContent(content, targetURL, outputMode, outputPath); err != nil {
			log.Fatal().Err(err).Msg("Error writing content")
		}
		found = true
	}
}
