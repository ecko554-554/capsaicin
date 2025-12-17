package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ANSI Color Codes (Enhanced Cyberpunk Palette)
const (
	ColorReset     = "\033[0m"
	ColorRed       = "\033[31m"
	ColorGreen     = "\033[32m"
	ColorYellow    = "\033[33m"
	ColorBlue      = "\033[34m"
	ColorPurple    = "\033[35m"
	ColorCyan      = "\033[36m"
	ColorWhite     = "\033[37m"
	ColorBold      = "\033[1m"
	ColorNeonGreen = "\033[1;92m"
	ColorNeonCyan  = "\033[1;96m"
	ColorMagenta   = "\033[1;95m"
	ColorOrange    = "\033[38;5;208m"
	ColorPink      = "\033[38;5;205m"
	BgMagenta      = "\033[45m"
	BgRed          = "\033[41m"
)

// Result represents a single finding
type Result struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Size        int      `json:"size"`
	WordCount   int      `json:"word_count"`
	LineCount   int      `json:"line_count"`
	Critical    bool     `json:"critical"`
	Method      string   `json:"method"`
	Timestamp   string   `json:"timestamp"`
	Server      string   `json:"server,omitempty"`
	PoweredBy   string   `json:"powered_by,omitempty"`
	CurlCommand string   `json:"curl_command"`
	UserAgent   string   `json:"user_agent"`
	SecretFound bool     `json:"secret_found"`
	SecretTypes []string `json:"secret_types,omitempty"`
	WAFDetected string   `json:"waf_detected,omitempty"`
}

// Task represents a scanning task with depth tracking
type Task struct {
	TargetURL string
	Path      string
	Depth     int
}

// ResponseSignature holds the characteristics of a response for filtering
type ResponseSignature struct {
	StatusCode int
	Size       int
	WordCount  int
	LineCount  int
}

// Config holds all configuration options
type Config struct {
	TargetURL     string
	Wordlist      string
	Threads       int
	Extensions    []string
	Timeout       int
	OutputFile    string
	HTMLReport    string
	Verbose       bool
	MaxDepth      int
	CustomHeaders map[string]string
}

// Stats holds runtime statistics
type Stats struct {
	Total      int64
	Processed  int64
	Found      int64
	Errors     int64
	Secrets    int64
	WAFHits    int64
	StartTime  time.Time
	ErrorMutex sync.Mutex
}

// SecretPattern holds regex patterns for secret detection
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// WAFSignature holds detection patterns for WAF identification
type WAFSignature struct {
	Name          string
	ServerHeader  string
	CustomHeader  string
	CookiePattern string
}

// Implement flag.Value interface for header flags - GLOBAL SCOPE FIX
type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

// Modern User-Agent pool for rotation (anti-fingerprinting)
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
}

// HTTP Client with custom transport for performance
var httpClient *http.Client

// SENSORS: Secret detection patterns
var secretPatterns = []SecretPattern{
	{
		Name:    "AWS Access Key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		Name:    "Generic API Key",
		Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)["\s:=]+[a-zA-Z0-9_\-]{20,}`),
	},
	{
		Name:    "Private Key",
		Pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
	{
		Name:    "JWT Token",
		Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	},
	{
		Name:    "Slack Token",
		Pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`),
	},
	{
		Name:    "Google API Key",
		Pattern: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	},
}

// WAF Detection Signatures
var wafSignatures = []WAFSignature{
	{
		Name:          "Cloudflare",
		ServerHeader:  "cloudflare",
		CookiePattern: "__cfduid",
	},
	{
		Name:         "AWS WAF",
		CustomHeader: "X-Amz-Cf-Id",
	},
	{
		Name:         "Akamai",
		ServerHeader: "AkamaiGHost",
	},
	{
		Name:         "Imperva",
		CustomHeader: "X-Iinfo",
	},
	{
		Name:          "F5 BigIP",
		CookiePattern: "BIGipServer",
	},
	{
		Name:         "Sucuri",
		ServerHeader: "Sucuri",
	},
	{
		Name:         "StackPath",
		ServerHeader: "StackPath",
	},
	{
		Name:         "Wordfence",
		CustomHeader: "X-Wf-",
	},
}

func main() {
	showBanner()

	// Parse command line flags
	config := parseFlags()

	// Check for STDIN input (multi-target mode)
	targets := []string{}
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		fmt.Printf("%s[*]%s Multi-Target Mode: Reading targets from STDIN...\n", ColorNeonCyan, ColorReset)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text())
			if target != "" && !strings.HasPrefix(target, "#") {
				targets = append(targets, target)
			}
		}
		fmt.Printf("%s[✓]%s Loaded %d targets from STDIN\n", ColorNeonGreen, ColorReset, len(targets))
	} else if config.TargetURL != "" {
		targets = append(targets, config.TargetURL)
	} else {
		fmt.Printf("%s[ERROR]%s No target specified. Use -u flag or pipe targets via STDIN\n", ColorRed+ColorBold, ColorReset)
		os.Exit(1)
	}

	// Validate configuration
	if err := validateConfig(&config, targets); err != nil {
		fmt.Printf("%s[ERROR]%s %s\n", ColorRed+ColorBold, ColorReset, err)
		os.Exit(1)
	}

	// Initialize HTTP client with timeout
	httpClient = &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        config.Threads * 2,
			MaxIdleConnsPerHost: config.Threads,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Display Attack Configuration
	showAttackConfig(config, targets)

	// Load wordlist
	words, err := loadWordlist(config.Wordlist)
	if err != nil {
		fmt.Printf("%s[ERROR]%s Failed to load wordlist: %s\n", ColorRed+ColorBold, ColorReset, err)
		os.Exit(1)
	}

	// Initialize statistics
	initialTaskCount := int64(len(targets) * len(words) * (1 + len(config.Extensions)))
	stats := &Stats{
		Total:     initialTaskCount,
		StartTime: time.Now(),
	}

	// Results collection
	var results []Result
	var resultsMutex sync.Mutex

	// Scanned directories tracker (per target)
	scannedDirs := make(map[string]map[string]bool)
	var dirMutex sync.Mutex

	// Start fuzzing engine
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════════╗%s\n", ColorMagenta+ColorBold, ColorReset)
	fmt.Printf("%s║                     🔥 ATTACK INITIATED 🔥                     ║%s\n", ColorMagenta+ColorBold, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════════╝%s\n\n", ColorMagenta+ColorBold, ColorReset)

	// Worker pool pattern with channels
	taskChan := make(chan Task, config.Threads*2)
	resultChan := make(chan Result, config.Threads*2)
	newTaskChan := make(chan Task, config.Threads*2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Progress reporter goroutine
	if !config.Verbose {
		go progressReporter(stats, ctx)
	}

	// Result collector goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range resultChan {
			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()

			if !config.Verbose {
				printResult(result)
			}
		}
	}()

	// Recursive task manager goroutine
	if config.MaxDepth > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for newTask := range newTaskChan {
				dirMutex.Lock()
				if scannedDirs[newTask.TargetURL] == nil {
					scannedDirs[newTask.TargetURL] = make(map[string]bool)
				}
				if !scannedDirs[newTask.TargetURL][newTask.Path] && newTask.Depth <= config.MaxDepth {
					scannedDirs[newTask.TargetURL][newTask.Path] = true
					dirMutex.Unlock()

					for _, word := range words {
						task := Task{
							TargetURL: newTask.TargetURL,
							Path:      strings.TrimSuffix(newTask.Path, "/") + "/" + word,
							Depth:     newTask.Depth,
						}
						taskChan <- task
						atomic.AddInt64(&stats.Total, 1)

						for _, ext := range config.Extensions {
							taskWithExt := Task{
								TargetURL: newTask.TargetURL,
								Path:      strings.TrimSuffix(newTask.Path, "/") + "/" + word + ext,
								Depth:     newTask.Depth,
							}
							taskChan <- taskWithExt
							atomic.AddInt64(&stats.Total, 1)
						}
					}
				} else {
					dirMutex.Unlock()
				}
			}
		}()
	}

	// Spawn worker pool
	var workerWG sync.WaitGroup
	for i := 0; i < config.Threads; i++ {
		workerWG.Add(1)
		go worker(i, config, taskChan, resultChan, newTaskChan, stats, &workerWG, &scannedDirs, &dirMutex, targets, words)
	}

	// Feed initial tasks to workers
	go func() {
		for _, target := range targets {
			signatures := performCalibration(target, config)

			for _, word := range words {
				task := Task{TargetURL: target, Path: word, Depth: 1}
				taskChan <- task

				for _, ext := range config.Extensions {
					taskWithExt := Task{TargetURL: target, Path: word + ext, Depth: 1}
					taskChan <- taskWithExt
				}
			}

			_ = signatures
		}
	}()

	// Wait for all tasks to complete
	go func() {
		workerWG.Wait()
		close(taskChan)
		close(resultChan)
		if config.MaxDepth > 0 {
			close(newTaskChan)
		}
	}()

	// Wait for result collector
	wg.Wait()
	cancel()

	// Final output
	elapsed := time.Since(stats.StartTime)
	fmt.Printf("\n\n%s╔════════════════════════════════════════════════════════════════╗%s\n", ColorNeonGreen+ColorBold, ColorReset)
	fmt.Printf("%s║                     💀 ATTACK COMPLETED 💀                     ║%s\n", ColorNeonGreen+ColorBold, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════════╝%s\n", ColorNeonGreen+ColorBold, ColorReset)
	fmt.Printf("\n%s┌─ STATISTICS ─────────────────────────────────────────────────┐%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s│%s Total Requests:     %s%d%s\n", ColorCyan, ColorReset, ColorBold, stats.Processed, ColorReset)
	fmt.Printf("%s│%s Findings:           %s%d%s\n", ColorCyan, ColorReset, ColorNeonGreen+ColorBold, stats.Found, ColorReset)
	fmt.Printf("%s│%s Secrets Found:      %s%d%s\n", ColorCyan, ColorReset, ColorRed+ColorBold, stats.Secrets, ColorReset)
	fmt.Printf("%s│%s WAF Detections:     %s%d%s\n", ColorCyan, ColorReset, ColorMagenta+ColorBold, stats.WAFHits, ColorReset)
	fmt.Printf("%s│%s Errors:             %d\n", ColorCyan, ColorReset, stats.Errors)
	fmt.Printf("%s│%s Duration:           %s\n", ColorCyan, ColorReset, elapsed.Round(time.Millisecond))
	fmt.Printf("%s│%s Req/s:              %.2f\n", ColorCyan, ColorReset, float64(stats.Processed)/elapsed.Seconds())
	fmt.Printf("%s└──────────────────────────────────────────────────────────────┘%s\n\n", ColorCyan, ColorReset)

	// Save results
	if config.OutputFile != "" {
		if err := saveResults(results, config.OutputFile); err != nil {
			fmt.Printf("%s[ERROR]%s Failed to save results: %s\n", ColorRed+ColorBold, ColorReset, err)
		} else {
			fmt.Printf("%s[✓]%s Results saved to: %s\n", ColorNeonGreen, ColorReset, config.OutputFile)
		}
	}

	if config.HTMLReport != "" {
		if err := generateHTMLReport(results, config.HTMLReport, config); err != nil {
			fmt.Printf("%s[ERROR]%s Failed to generate HTML report: %s\n", ColorRed+ColorBold, ColorReset, err)
		} else {
			fmt.Printf("%s[✓]%s HTML report saved to: %s\n", ColorNeonGreen, ColorReset, config.HTMLReport)
		}
	}
}

func showBanner() {
	banner := `
   ██████╗ █████╗ ██████╗ ███████╗ █████╗ ██╗ ██████╗██╗███╗   ██╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║██╔════╝██║████╗  ██║
  ██║     ███████║██████╔╝███████╗███████║██║██║     ██║██╔██╗ ██║
  ██║     ██╔══██║██╔═══╝ ╚════██║██╔══██║██║██║     ██║██║╚██╗██║
  ╚██████╗██║  ██║██║     ███████║██║  ██║██║╚██████╗██║██║ ╚████║
   ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝╚═╝  ╚═══╝
`
	subtitle := `
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  █                      v1.5 RED TEAM EDITION                   █
  █            Advanced Web Directory Fuzzer + WAF Hunter        █
  █                     Developer: Hawtsauce                     █
  █                Intelligence > Speed > Stealth                █
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
`
	fmt.Printf("%s%s%s", ColorMagenta+ColorBold, banner, ColorReset)
	fmt.Printf("%s%s%s\n", ColorNeonCyan, subtitle, ColorReset)
}

func showAttackConfig(config Config, targets []string) {
	fmt.Printf("\n%s╔══ ATTACK CONFIGURATION ══════════════════════════════════════╗%s\n", ColorOrange+ColorBold, ColorReset)
	fmt.Printf("%s║%s\n", ColorOrange, ColorReset)

	// Targets
	if len(targets) == 1 {
		fmt.Printf("%s║%s   🎯 Target:           %s%s%s\n", ColorOrange, ColorReset, ColorBold, targets[0], ColorReset)
	} else {
		fmt.Printf("%s║%s   🎯 Targets:         %s%d domains%s\n", ColorOrange, ColorReset, ColorBold, len(targets), ColorReset)
	}

	// Wordlist
	fmt.Printf("%s║%s   📝 Wordlist:         %s\n", ColorOrange, ColorReset, config.Wordlist)

	// Threads
	fmt.Printf("%s║%s   ⚡ Threads:          %s%d%s\n", ColorOrange, ColorReset, ColorBold, config.Threads, ColorReset)

	// Extensions
	if len(config.Extensions) > 0 {
		fmt.Printf("%s║%s   📦 Extensions:       %s\n", ColorOrange, ColorReset, strings.Join(config.Extensions, ", "))
	}

	// Recursive
	if config.MaxDepth > 0 {
		fmt.Printf("%s║%s   🔄 Recursive:        %sEnabled (Depth: %d)%s\n", ColorOrange, ColorReset, ColorNeonGreen, config.MaxDepth, ColorReset)
	}

	// Custom Headers
	if len(config.CustomHeaders) > 0 {
		fmt.Printf("%s║%s   🔑 Custom Headers:   %s%d configured%s\n", ColorOrange, ColorReset, ColorBold, len(config.CustomHeaders), ColorReset)
		for key := range config.CustomHeaders {
			fmt.Printf("%s║%s      └─ %s\n", ColorOrange, ColorReset, key)
		}
	}

	// Modules
	fmt.Printf("%s║%s\n", ColorOrange, ColorReset)
	fmt.Printf("%s║%s   %s🛡️  WAF Detection:%s      ACTIVE\n", ColorOrange, ColorReset, ColorMagenta, ColorReset)
	fmt.Printf("%s║%s   %s🔐 Secret Scanner:%s      ACTIVE (%d patterns)\n", ColorOrange, ColorReset, ColorRed, ColorReset, len(secretPatterns))
	fmt.Printf("%s║%s   %s🔥 Method Fuzzing:%s     ACTIVE\n", ColorOrange, ColorReset, ColorYellow, ColorReset)
	fmt.Printf("%s║%s   %s🧠 Smart Calibration:%s  ACTIVE\n", ColorOrange, ColorReset, ColorCyan, ColorReset)

	fmt.Printf("%s║%s\n", ColorOrange, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", ColorOrange+ColorBold, ColorReset)
}

func parseFlags() Config {
	config := Config{
		CustomHeaders: make(map[string]string),
	}

	var headers headerFlags

	flag.StringVar(&config.TargetURL, "u", "", "Target URL (or use STDIN for multiple targets)")
	flag.StringVar(&config.Wordlist, "w", "", "Wordlist path (required)")
	flag.IntVar(&config.Threads, "t", 50, "Number of concurrent threads")
	extensions := flag.String("x", "", "Extensions (comma-separated, e.g., php,html,txt)")
	flag.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.StringVar(&config.OutputFile, "o", "", "Output file (JSON format)")
	flag.StringVar(&config.HTMLReport, "html", "", "Generate HTML report")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode (print every request)")
	flag.IntVar(&config.MaxDepth, "depth", 0, "Recursive scanning depth (0=disabled)")
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")

	// Custom usage
	flag.Usage = func() {
		fmt.Printf("%s", ColorNeonCyan+ColorBold)
		fmt.Printf(`
  ╔═══════════════════════════════════════════════════════════════╗
  ║           CAPSAICIN v1.5 RED TEAM - Usage Guide               ║
  ╚═══════════════════════════════════════════════════════════════╝
`)
		fmt.Printf("%s\n", ColorReset)
		fmt.Printf("%sREQUIRED FLAGS:%s\n", ColorOrange+ColorBold, ColorReset)
		fmt.Printf("  -u string       Target URL (or pipe via STDIN)\n")
		fmt.Printf("  -w string       Path to wordlist file\n\n")

		fmt.Printf("%sOPTIONAL FLAGS:%s\n", ColorOrange+ColorBold, ColorReset)
		fmt.Printf("  -t int         Concurrent threads (default: 50)\n")
		fmt.Printf("  -x string       Extensions (comma-separated)\n")
		fmt.Printf("  -H string       Custom headers (repeatable)\n")
		fmt.Printf("  --timeout int  Request timeout in seconds (default: 10)\n")
		fmt.Printf("  --depth int    Recursive scanning depth (0=disabled)\n")
		fmt.Printf("  -v             Verbose mode\n")
		fmt.Printf("  -o string       JSON output file\n")
		fmt.Printf("  --html string  HTML report file\n\n")

		fmt.Printf("%sEXAMPLES:%s\n", ColorNeonGreen+ColorBold, ColorReset)
		fmt.Printf("  # Basic scan\n")
		fmt.Printf("  capsaicin -u https://target.com -w wordlist.txt\n\n")
		fmt.Printf("  # With authentication\n")
		fmt.Printf("  capsaicin -u https://api.target.com -w words.txt \\\n")
		fmt.Printf("    -H \"Authorization: Bearer token123\" \\\n")
		fmt.Printf("    -H \"Cookie: session=abc\"\n\n")
		fmt.Printf("  # Multi-target scan\n")
		fmt.Printf("  cat targets.txt | capsaicin -w wordlist.txt -t 100\n\n")
	}

	flag.Parse()

	// Parse extensions
	if *extensions != "" {
		config.Extensions = strings.Split(*extensions, ",")
		for i := range config.Extensions {
			config.Extensions[i] = strings.TrimSpace(config.Extensions[i])
			if !strings.HasPrefix(config.Extensions[i], ".") {
				config.Extensions[i] = "." + config.Extensions[i]
			}
		}
	}

	// Parse custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config.CustomHeaders[key] = value
		}
	}

	return config
}

func validateConfig(config *Config, targets []string) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	for i := range targets {
		if !strings.HasPrefix(targets[i], "http://") && !strings.HasPrefix(targets[i], "https://") {
			targets[i] = "http://" + targets[i]
		}
	}

	if config.Wordlist == "" {
		return fmt.Errorf("wordlist is required (-w)")
	}
	if _, err := os.Stat(config.Wordlist); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file not found: %s", config.Wordlist)
	}
	return nil
}

// BRAIN 1: Smart Auto-Calibration
func performCalibration(targetURL string, config Config) []ResponseSignature {
	signatures := make([]ResponseSignature, 0, 3)
	randomPaths := []string{
		fmt.Sprintf("/capsaicin_calibration_%d", rand.Intn(999999)),
		fmt.Sprintf("/random_nonexistent_%d", rand.Intn(999999)),
		fmt.Sprintf("/test_404_path_%d", rand.Intn(999999)),
	}

	fmt.Printf("%s[🧠 BRAIN-1]%s Calibrating: %s\n", ColorCyan+ColorBold, ColorReset, targetURL)

	for _, path := range randomPaths {
		url := strings.TrimSuffix(targetURL, "/") + path
		sig := fetchSignature(url, config)
		if sig != nil {
			signatures = append(signatures, *sig)
		}
	}

	return signatures
}

func fetchSignature(url string, config Config) *ResponseSignature {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	// Apply custom headers
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return &ResponseSignature{
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(string(body))),
		LineCount:  strings.Count(string(body), "\n") + 1,
	}
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

// Worker function with all advanced features
func worker(id int, config Config, tasks <-chan Task, results chan<- Result, newTasks chan<- Task,
	stats *Stats, wg *sync.WaitGroup, scannedDirs *map[string]map[string]bool, dirMutex *sync.Mutex,
	targets []string, words []string) {
	defer wg.Done()

	consecutiveErrors := 0
	maxConsecutiveErrors := 5

	targetSignatures := make(map[string][]ResponseSignature)
	for _, target := range targets {
		targetSignatures[target] = performCalibration(target, config)
	}

	for task := range tasks {
		url := strings.TrimSuffix(task.TargetURL, "/") + "/" + strings.TrimPrefix(task.Path, "/")

		if config.Verbose {
			fmt.Printf("%s[→]%s Testing: %s\n", ColorCyan, ColorReset, url)
		}

		userAgent := getRandomUserAgent()
		result, bodyContent, err := makeRequestWithUA(url, "GET", userAgent, config)
		atomic.AddInt64(&stats.Processed, 1)

		if err != nil {
			atomic.AddInt64(&stats.Errors, 1)
			consecutiveErrors++

			if consecutiveErrors >= maxConsecutiveErrors {
				time.Sleep(2 * time.Second)
				consecutiveErrors = 0
			}
			continue
		}

		consecutiveErrors = 0

		if matchesSignature(result, targetSignatures[task.TargetURL]) {
			continue
		}

		// HTTP Method Fuzzing on 405
		if result.StatusCode == 405 {
			alternativeMethods := []string{"POST", "PUT", "DELETE", "PATCH"}
			for _, method := range alternativeMethods {
				methodResult, methodBody, err := makeRequestWithUA(url, method, userAgent, config)
				if err == nil && (methodResult.StatusCode == 200 || methodResult.StatusCode == 201 || methodResult.StatusCode == 204) {
					methodResult.Method = method
					methodResult.Critical = true

					if secrets := detectSecrets(methodBody); len(secrets) > 0 {
						methodResult.SecretFound = true
						methodResult.SecretTypes = secrets
						atomic.AddInt64(&stats.Secrets, 1)
					}

					atomic.AddInt64(&stats.Found, 1)
					results <- *methodResult
					break
				}
			}
		}

		if isInteresting(result) {
			atomic.AddInt64(&stats.Found, 1)

			// Secret Detection
			if result.StatusCode == 200 && len(bodyContent) > 0 {
				if secrets := detectSecrets(bodyContent); len(secrets) > 0 {
					result.SecretFound = true
					result.SecretTypes = secrets
					atomic.AddInt64(&stats.Secrets, 1)
				}
			}

			// Active 403/401 Bypass
			if result.StatusCode == 403 || result.StatusCode == 401 {
				bypassResult, bypassBody := attemptBypass(url, userAgent, config)
				if bypassResult != nil && (bypassResult.StatusCode == 200 || bypassResult.StatusCode == 302) {
					bypassResult.Critical = true

					if secrets := detectSecrets(bypassBody); len(secrets) > 0 {
						bypassResult.SecretFound = true
						bypassResult.SecretTypes = secrets
						atomic.AddInt64(&stats.Secrets, 1)
					}

					results <- *bypassResult

					mutations := generateMutations(task.Path)
					for _, mutation := range mutations {
						mutatedURL := strings.TrimSuffix(task.TargetURL, "/") + "/" + strings.TrimPrefix(mutation, "/")
						mutatedResult, mutatedBody, err := makeRequestWithUA(mutatedURL, "GET", userAgent, config)
						if err == nil && isInteresting(mutatedResult) && !matchesSignature(mutatedResult, targetSignatures[task.TargetURL]) {
							if secrets := detectSecrets(mutatedBody); len(secrets) > 0 {
								mutatedResult.SecretFound = true
								mutatedResult.SecretTypes = secrets
								atomic.AddInt64(&stats.Secrets, 1)
							}
							results <- *mutatedResult
						}
					}
				}
			}

			// Recursive Discovery
			if config.MaxDepth > 0 && task.Depth < config.MaxDepth {
				if isDirectory(result) {
					dirPath := extractPath(url)
					if config.Verbose {
						fmt.Printf("%s[RECURSE]%s Found directory: %s (Depth: %d)\n",
							ColorYellow, ColorReset, dirPath, task.Depth)
					}
					newTasks <- Task{
						TargetURL: task.TargetURL,
						Path:      dirPath,
						Depth:     task.Depth + 1,
					}
				}
			}

			results <- *result
		}
	}
}

func makeRequestWithUA(url, method, userAgent string, config Config) (*Result, string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", userAgent)

	// NEW FEATURE: Apply custom headers to ALL requests
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	bodyContent := string(body)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	result := &Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     method,
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     server,
		PoweredBy:  poweredBy,
		UserAgent:  userAgent,
	}

	// NEW FEATURE: WAF Detection
	if wafName := detectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	}

	result.CurlCommand = generateCurlCommand(url, method, userAgent, config)

	return result, bodyContent, nil
}

// NEW FEATURE: WAF Detection Engine
func detectWAF(resp *http.Response) string {
	for _, waf := range wafSignatures {
		// Check Server header
		if waf.ServerHeader != "" {
			if server := resp.Header.Get("Server"); strings.Contains(strings.ToLower(server), strings.ToLower(waf.ServerHeader)) {
				return waf.Name
			}
		}

		// Check custom headers
		if waf.CustomHeader != "" {
			for header := range resp.Header {
				if strings.Contains(strings.ToLower(header), strings.ToLower(waf.CustomHeader)) {
					return waf.Name
				}
			}
		}

		// Check cookies
		if waf.CookiePattern != "" {
			for _, cookie := range resp.Cookies() {
				if strings.Contains(cookie.Name, waf.CookiePattern) {
					return waf.Name
				}
			}
		}
	}

	return ""
}

func generateCurlCommand(url, method, userAgent string, config Config) string {
	cmd := fmt.Sprintf(`curl -X %s "%s" -H "User-Agent: %s"`, method, url, userAgent)
	for key, value := range config.CustomHeaders {
		cmd += fmt.Sprintf(` -H "%s: %s"`, key, value)
	}
	return cmd
}

func detectSecrets(content string) []string {
	var foundSecrets []string
	secretMap := make(map[string]bool)

	for _, pattern := range secretPatterns {
		if pattern.Pattern.MatchString(content) {
			if !secretMap[pattern.Name] {
				foundSecrets = append(foundSecrets, pattern.Name)
				secretMap[pattern.Name] = true
			}
		}
	}

	return foundSecrets
}

func attemptBypass(url, userAgent string, config Config) (*Result, string) {
	bypassHeaders := map[string]string{
		"X-Forwarded-For":           "127.0.0.1",
		"X-Original-URL":            extractPath(url),
		"X-Rewrite-URL":             extractPath(url),
		"X-Custom-IP-Authorization": "127.0.0.1",
		"Client-IP":                 "127.0.0.1",
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, ""
	}

	req.Header.Set("User-Agent", userAgent)

	// Apply custom headers first
	for key, value := range config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// Then apply bypass headers
	for key, value := range bypassHeaders {
		req.Header.Set(key, value)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ""
	}

	bodyContent := string(body)
	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	curlCmd := fmt.Sprintf(`curl -X GET "%s" -H "User-Agent: %s" -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: %s"`,
		url, userAgent, extractPath(url))

	result := &Result{
		URL:        url + " [BYPASS]",
		StatusCode: resp.StatusCode,
		Size:       len(body),
		WordCount:  len(strings.Fields(bodyContent)),
		LineCount:  strings.Count(bodyContent, "\n") + 1,
		Method:     "GET+BYPASS",
		Timestamp:  time.Now().Format(time.RFC3339),
		Server:     server,
		PoweredBy:  poweredBy,
		UserAgent:  userAgent,
		CurlCommand: curlCmd,
	}

	if wafName := detectWAF(resp); wafName != "" {
		result.WAFDetected = wafName
	}

	return result, bodyContent
}

func generateMutations(path string) []string {
	mutations := []string{
		path + ".bak",
		path + ".old",
		path + ".backup",
		path + "~",
		path + ".swp",
		"." + path + ".swp",
		"_" + path,
		path + ".txt",
		path + ".orig",
	}

	if strings.Contains(path, ".") {
		parts := strings.Split(path, ".")
		base := strings.Join(parts[:len(parts)-1], ".")
		mutations = append(mutations, base+".bak."+parts[len(parts)-1])
	}

	return mutations
}

func isDirectory(result *Result) bool {
	if result.StatusCode == 301 || result.StatusCode == 302 || result.StatusCode == 403 {
		return true
	}
	if strings.HasSuffix(result.URL, "/") {
		return true
	}
	return false
}

func matchesSignature(result *Result, signatures []ResponseSignature) bool {
	for _, sig := range signatures {
		if result.StatusCode == sig.StatusCode {
			if sig.Size == 0 {
				continue
			}
			sizeDiff := float64(abs(result.Size-sig.Size)) / float64(sig.Size)
			if sizeDiff < 0.05 {
				return true
			}
		}
	}
	return false
}

func isInteresting(result *Result) bool {
	if result.StatusCode >= 200 && result.StatusCode < 400 {
		return true
	}
	if result.StatusCode == 401 || result.StatusCode == 403 {
		return true
	}
	return false
}

func printResult(result Result) {
	var color string
	switch {
	case result.StatusCode >= 200 && result.StatusCode < 300:
		color = ColorNeonGreen
	case result.StatusCode >= 300 && result.StatusCode < 400:
		color = ColorBlue
	case result.StatusCode >= 400 && result.StatusCode < 500:
		color = ColorRed
	case result.StatusCode >= 500:
		color = ColorYellow
	default:
		color = ColorWhite
	}

	critical := ""
	if result.Critical {
		critical = ColorOrange + ColorBold + " [⚡ CRITICAL]" + ColorReset
	}

	// WAF Detection output with high visibility
	wafInfo := ""
	if result.WAFDetected != "" {
		wafInfo = BgMagenta + ColorWhite + ColorBold + " [🔥 WAF: " + result.WAFDetected + "] " + ColorReset
	}

	secretInfo := ""
	if result.SecretFound {
		secretInfo = BgRed + ColorWhite + ColorBold + " [🔐 " + strings.Join(result.SecretTypes, ", ") + "] " + ColorReset
	}

	methodInfo := ""
	if result.Method != "GET" && result.Method != "GET+BYPASS" {
		methodInfo = ColorPurple + " [METHOD: " + result.Method + "]" + ColorReset
	}

	techInfo := ""
	if result.Server != "" {
		techInfo += fmt.Sprintf(" [%s]", result.Server)
	}
	if result.PoweredBy != "" {
		techInfo += fmt.Sprintf(" [%s]", result.PoweredBy)
	}

	fmt.Printf("%s%-4d%s │ Size: %s%-7d%s │ %s%s%s%s%s%s%s%s\n",
		color+ColorBold, result.StatusCode, ColorReset,
		color, result.Size, ColorReset,
		color, result.URL, ColorReset,
		ColorCyan+techInfo+ColorReset,
		methodInfo,
		critical,
		wafInfo,
		secretInfo)
}

func progressReporter(stats *Stats, ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := time.Since(stats.StartTime).Seconds()
			reqPerSec := float64(atomic.LoadInt64(&stats.Processed)) / elapsed
			total := atomic.LoadInt64(&stats.Total)
			processed := atomic.LoadInt64(&stats.Processed)
			var progress float64
			if total > 0 {
				progress = float64(processed) / float64(total) * 100
			}

			fmt.Printf("\r%s[%.1f%%] │ [⚡ %d req/s] │ [✓ %d] │ [🔐 %d] │ [🔥 %d WAF] │ [✗ %d]%s",
				ColorNeonCyan+ColorBold,
				progress,
				int(reqPerSec),
				atomic.LoadInt64(&stats.Found),
				atomic.LoadInt64(&stats.Secrets),
				atomic.LoadInt64(&stats.WAFHits),
				atomic.LoadInt64(&stats.Errors),
				ColorReset)
		}
	}
}

func saveResults(results []Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func generateHTMLReport(results []Result, filename string, config Config) error {
	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Capsaicin v1.5 RED TEAM Report</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
			background: linear-gradient(135deg, #0f0c29 0%%, #302b63 50%%, #24243e 100%%);
			color: #fff;
			padding: 20px;
		}
		.container { max-width: 1600px; margin: 0 auto; }
		.header {
			background: linear-gradient(135deg, #ff0080 0%%, #ff8c00 50%%, #ff0080 100%%);
			padding: 40px;
			border-radius: 15px;
			margin-bottom: 30px;
			box-shadow: 0 15px 35px rgba(255,0,128,0.4);
			text-align: center;
		}
		h1 { font-size: 3em; margin-bottom: 10px; text-shadow: 0 0 20px rgba(255,255,255,0.5); }
		.stats {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
			gap: 20px;
			margin-bottom: 30px;
		}
		.stat-card {
			background: rgba(255,255,255,0.1);
			padding: 25px;
			border-radius: 12px;
			backdrop-filter: blur(10px);
			border: 1px solid rgba(255,255,255,0.2);
			transition: all 0.3s;
		}
		.stat-card:hover {
			transform: translateY(-5px);
			box-shadow: 0 10px 25px rgba(255,0,128,0.3);
		}
		.stat-value { font-size: 2.2em; font-weight: bold; color: #ff0080; }
		.search-box {
			margin-bottom: 20px;
			padding: 20px;
			background: rgba(255,255,255,0.1);
			border-radius: 12px;
			backdrop-filter: blur(10px);
		}
		#searchInput {
			width: 100%%;
			padding: 15px;
			font-size: 16px;
			border: 2px solid #ff0080;
			border-radius: 8px;
			background: rgba(0,0,0,0.3);
			color: #fff;
		}
		table {
			width: 100%%;
			background: rgba(255,255,255,0.05);
			border-radius: 12px;
			overflow: hidden;
			box-shadow: 0 5px 25px rgba(0,0,0,0.5);
		}
		th {
			background: linear-gradient(135deg, #ff0080, #ff8c00);
			padding: 18px;
			text-align: left;
			font-weight: 700;
			text-transform: uppercase;
			font-size: 0.9em;
		}
		td {
			padding: 15px 18px;
			border-bottom: 1px solid rgba(255,255,255,0.1);
		}
		tr:hover { background: rgba(255,0,128,0.15); }
		.status-200 { color: #00ff88; font-weight: bold; }
		.status-300 { color: #4da6ff; font-weight: bold; }
		.status-400 { color: #ff4444; font-weight: bold; }
		.status-500 { color: #ffaa00; font-weight: bold; }
		.critical { 
			background: rgba(255,140,0,0.3);
			padding: 4px 10px;
			border-radius: 5px;
			font-weight: bold;
			border: 1px solid #ff8c00;
		}
		.secret-badge {
			display: inline-block;
			background: rgba(255,0,0,0.4);
			border: 2px solid #ff0000;
			padding: 4px 12px;
			border-radius: 6px;
			font-weight: bold;
			font-size: 0.85em;
			animation: pulse 2s infinite;
		}
		.waf-badge {
			display: inline-block;
			background: rgba(255,0,255,0.4);
			border: 2px solid #ff00ff;
			padding: 4px 12px;
			border-radius: 6px;
			font-weight: bold;
			font-size: 0.85em;
			animation: glow 2s ease-in-out infinite;
		}
		@keyframes pulse {
			0%%, 100%% { opacity: 1; }
			50%% { opacity: 0.6; }
		}
		@keyframes glow {
			0%%, 100%% { box-shadow: 0 0 5px #ff00ff; }
			50%% { box-shadow: 0 0 20px #ff00ff; }
		}
		.tech-badge {
			display: inline-block;
			background: rgba(100,200,255,0.2);
			padding: 3px 10px;
			border-radius: 5px;
			margin-right: 5px;
			font-size: 0.9em;
		}
		.curl-btn {
			background: linear-gradient(135deg, #ff0080, #ff8c00);
			color: #fff;
			border: none;
			padding: 8px 15px;
			border-radius: 6px;
			cursor: pointer;
			font-size: 0.9em;
			font-weight: bold;
			transition: all 0.3s;
		}
		.curl-btn:hover { 
			transform: scale(1.05);
			box-shadow: 0 5px 15px rgba(255,0,128,0.4);
		}
		code {
			background: rgba(0,0,0,0.6);
			padding: 3px 8px;
			border-radius: 4px;
			font-family: 'Courier New', monospace;
			font-size: 0.9em;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🌶️ CAPSAICIN v1.5</h1>
			<h2 style="color: #fff; opacity: 0.9;">RED TEAM EDITION</h2>
			<p style="opacity: 0.8; margin-top: 15px; font-size: 1.1em;">Generated: %s</p>
		</div>

		<div class="stats">
			<div class="stat-card">
				<div class="stat-value">%d</div>
				<div>Total Findings</div>
			</div>
			<div class="stat-card">
				<div class="stat-value" style="color: #00ff88;">%d</div>
				<div>Success (2xx)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value" style="color: #4da6ff;">%d</div>
				<div>Redirects (3xx)</div>
			</div>
			<div class="stat-card">
				<div class="stat-value" style="color: #ff8c00;">%d</div>
				<div>Critical Bypasses</div>
			</div>
			<div class="stat-card">
				<div class="stat-value" style="color: #ff0000;">%d</div>
				<div>🔐 Secrets</div>
			</div>
			<div class="stat-card">
				<div class="stat-value" style="color: #ff00ff;">%d</div>
				<div>🔥 WAF Detected</div>
			</div>
		</div>

		<div class="search-box">
			<input type="text" id="searchInput" placeholder="🔍 Search findings (URL, status, server, secrets, WAF...)">
		</div>

		<table id="resultsTable">
			<thead>
				<tr>
					<th>Status</th>
					<th>URL</th>
					<th>Size</th>
					<th>Technology</th>
					<th>Security</th>
					<th>Action</th>
				</tr>
			</thead>
			<tbody>
				%s
			</tbody>
		</table>
	</div>

	<script>
		document.getElementById('searchInput').addEventListener('input', function(e) {
			const searchTerm = e.target.value.toLowerCase();
			const rows = document.querySelectorAll('#resultsTable tbody tr');
			
			rows.forEach(row => {
				const text = row.textContent.toLowerCase();
				row.style.display = text.includes(searchTerm) ? '' : 'none';
			});
		});

		function copyCurl(cmd) {
			navigator.clipboard.writeText(cmd).then(() => {
				alert('✅ Curl command copied to clipboard!');
			});
		}
	</script>
</body>
</html>`

	var tableRows strings.Builder
	count2xx := 0
	count3xx := 0
	countCritical := 0
	countSecrets := 0
	countWAF := 0

	for _, result := range results {
		statusClass := "status-200"
		if result.StatusCode >= 300 && result.StatusCode < 400 {
			statusClass = "status-300"
			count3xx++
		} else if result.StatusCode >= 400 && result.StatusCode < 500 {
			statusClass = "status-400"
		} else if result.StatusCode >= 500 {
			statusClass = "status-500"
		} else if result.StatusCode >= 200 && result.StatusCode < 300 {
			count2xx++
		}

		if result.Critical {
			countCritical++
		}
		if result.SecretFound {
			countSecrets++
		}
		if result.WAFDetected != "" {
			countWAF++
		}

		criticalBadge := ""
		if result.Critical {
			criticalBadge = `<span class="critical">⚡ CRITICAL</span>`
		}

		secretBadge := ""
		if result.SecretFound {
			secretBadge = fmt.Sprintf(`<span class="secret-badge">🔐 %s</span>`, strings.Join(result.SecretTypes, ", "))
		}

		wafBadge := ""
		if result.WAFDetected != "" {
			wafBadge = fmt.Sprintf(`<span class="waf-badge">🔥 WAF: %s</span>`, result.WAFDetected)
		}

		techInfo := ""
		if result.Server != "" {
			techInfo += fmt.Sprintf(`<span class="tech-badge">%s</span>`, result.Server)
		}
		if result.PoweredBy != "" {
			techInfo += fmt.Sprintf(`<span class="tech-badge">%s</span>`, result.PoweredBy)
		}

		securityInfo := secretBadge + " " + wafBadge

		escapedCurl := strings.ReplaceAll(result.CurlCommand, `"`, `&quot;`)

		tableRows.WriteString(fmt.Sprintf(`
				<tr>
					<td class="%s">%d</td>
					<td><code>%s</code> %s</td>
					<td>%d bytes</td>
					<td>%s</td>
					<td>%s</td>
					<td><button class="curl-btn" onclick='copyCurl("%s")'>Copy Curl</button></td>
				</tr>`,
			statusClass, result.StatusCode, result.URL, criticalBadge,
			result.Size, techInfo, securityInfo, escapedCurl))
	}

	finalHTML := fmt.Sprintf(htmlTemplate,
		time.Now().Format("2006-01-02 15:04:05"),
		len(results),
		count2xx,
		count3xx,
		countCritical,
		countSecrets,
		countWAF,
		tableRows.String())

	return os.WriteFile(filename, []byte(finalHTML), 0644)
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func extractPath(url string) string {
	parts := strings.SplitN(url, "/", 4)
	if len(parts) >= 4 {
		return "/" + parts[3]
	}
	return "/"
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
