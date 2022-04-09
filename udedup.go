package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
	"strconv"
	"strings"

	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Rules []*Rule `yaml:"rules"`
}
type Rule struct {
	Name        string `yaml:"name"`
	Filepath    string
	Tokens      []string     `yaml:"tokens"`
	Inquisitors []*Inquisitor     `yaml:"inquisitors"`
	Processors  []*Processor `yaml:"processors"`
}
type Inquisitor struct {
  // A simple key-only inquisitor (e.g., "dnsa", "contenthash")
  KeyInquisitor string
  // A key-value inquisitor, where a value is specified (e.g., "contentregex: \<img\>")
  KeyValueInquisitor map[string]string
}
type Processor struct {
	Urlencode    string `yaml:"urlencode,omitempty"`
	Base64Encode string `yaml:"base64encode,omitempty"`
}
// A Match is used to record the actual values obtained that lead to two URLs being declared duplicate.
type Match struct{
	isEquivalentURL bool
	Tokens map[string]string
	Inquisitors []MatchedInquisitor
}
type MatchedInquisitor struct{
  KeyInquisitor map[string]string
  KeyValueInquisitor map[string]bool
}
type URL struct {
	Value   string
	Domain  string
	IPAddrs []net.IP
	CName   string

	// Obtained from http.Get
	StatusCode    int
	ContentLength int64
	Protocol      string // "HTTP/1.0"
	ContentHash   string // hashed value of the content
	ContentRegex  map[string]bool // whether a given regex is found in the content
	HeaderRegex  map[string]bool // whether a given regex is found in the header

	// Example tokens: port, path, fragment, queryparams, ...
	Tokens map[string]string
}

// Create a custom YAML parser for Inquisitor as they contain Strings and Maps.
func (s *Inquisitor) UnmarshalYAML(unmarshal func(interface{}) error) error {
    if err := unmarshal(&(s.KeyInquisitor)); err != nil {
    }
    if err := unmarshal(&(s.KeyValueInquisitor)); err != nil {
    }
    return nil
}

// Equality between two URLs depends on the Rule struct
func (u *URL) equals(u2 *URL, rule *Rule) (bool, Match) {
	// Initialize empty return match
	match := Match{}
	match.Tokens = make(map[string]string)
	match.Inquisitors = make([]MatchedInquisitor, 0)

	// Short-circuit test: Compare Values
	if u.Value == u2.Value {
		match.isEquivalentURL = true
		return true, match
	}

	// Verify at least one definition of equality exists, else equality is not possible.
	if len(rule.Tokens) == 0 &&
		len(rule.Processors) == 0 &&
		len(rule.Inquisitors) == 0 {
		return false, match
	}

	// Compare Tokens
	for _, element := range rule.Tokens {
		needleToken, _ := u.Tokens[element]
		haystackToken, _ := u2.Tokens[element]
		if needleToken != haystackToken {
			return false, match
		}
		// Record the equal token in the match struct:
		match.Tokens[element] = needleToken
	}

	// Compare Processors

	// Compare Inquisitors
	for _, element := range rule.Inquisitors {
		// Check KeyInquisitors (a simple string)
		switch element.KeyInquisitor {
			case "dnsa":
				matchExists := false
				for _, uIP := range u.IPAddrs {
					for _, u2IP := range u2.IPAddrs {
						if uIP.Equal(u2IP) {
							matchExists = true
							// Record the match
							matchedInquisitor := MatchedInquisitor{}
							matchedInquisitor.KeyInquisitor = make(map[string]string)
							matchedInquisitor.KeyInquisitor[element.KeyInquisitor] = uIP.String()
							match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
						}
					}
				}
				if !matchExists {
					return false, match
				}
			case "dnscname":
				if u.CName != u2.CName {
					return false, match
				} else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyInquisitor = make(map[string]string)
					matchedInquisitor.KeyInquisitor[element.KeyInquisitor] = u.CName
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
				}
			case "statuscode":
				if u.StatusCode != u2.StatusCode {
					return false, match
				} else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyInquisitor = make(map[string]string)
					matchedInquisitor.KeyInquisitor[element.KeyInquisitor] = strconv.Itoa(u.StatusCode)
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
				}

			case "contentlength":
				if u.ContentLength != u2.ContentLength {
					return false, match
				} else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyInquisitor = make(map[string]string)
					matchedInquisitor.KeyInquisitor[element.KeyInquisitor] = strconv.FormatInt(u.ContentLength, 10)
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
				}
			case "contenthash":
				if u.ContentHash != u2.ContentHash {
					return false, match
				} else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyInquisitor = make(map[string]string)
					matchedInquisitor.KeyInquisitor[element.KeyInquisitor] = u.ContentHash
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
				}
			default:
				if(len(element.KeyInquisitor) > 0){
					fmt.Println("Unknown Inquisitor: " + element.KeyInquisitor)
				}
		}
		// Check KeyValueInquisitors. This for-loop should only be 1 deep as only 1 key-value exists in KeyValueInquisitor
		for key, value := range element.KeyValueInquisitor {
		  switch key {
			case "contentregex":
			  if u.ContentRegex[value] != u2.ContentRegex[value] {
				return false, match
			  } else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyValueInquisitor = make(map[string]bool)
					matchedInquisitor.KeyValueInquisitor[key+":"+value] = u.ContentRegex[value]
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
			  }
			case "headerregex":
			  if u.HeaderRegex[value] != u2.HeaderRegex[value] {
				return false, match
			  } else {
					// Record the match
					matchedInquisitor := MatchedInquisitor{}
					matchedInquisitor.KeyValueInquisitor = make(map[string]bool)
					matchedInquisitor.KeyValueInquisitor[key+":"+value] = u.HeaderRegex[value]
					match.Inquisitors = append(match.Inquisitors, matchedInquisitor)
			  }
			default:
			  // nothing
		  }
		}
    }

	// By this point, all definitions of equality have passed
	return true, match
}

// Convert a URL string into a URL struct.
func parseURL(input string) *URL {
	u, err := url.Parse(input)
	if err != nil {
		panic(err)
	}

	domain := u.Hostname()
	tokens := make(map[string]string)
	tokens["scheme"] = u.Scheme
	tokens["username"] = u.User.Username()
	tokens["password"], _ = u.User.Password()
	tokens["domain"] = domain
	tokens["port"] = u.Port()
	tokens["path"] = u.Path
	tokens["fragment"] = u.Fragment
	tokens["queryparams"] = u.RawQuery

	// If scheme is http and port is not specified, assume 80
	if(strings.ToLower(tokens["scheme"]) == "http" && tokens["port"] == "") {
		tokens["port"] = "80"
	}
	// If scheme is https and port is not specified, assume 443
	if(strings.ToLower(tokens["scheme"]) == "https" && tokens["port"] == "") {
		tokens["port"] = "443"
	}
	// If path is not specified, assume root "/"
	if(tokens["path"] == ""){
		tokens["path"] = "/"
	}
	ret := URL{
		Tokens: tokens,
		Domain: domain,
		Value:  input}
	return &ret
}

// Test whether a single URL exists within an array of URLs, as determined by the array of Rules
func existsWithin(needle *URL, haystack []*URL, rules []*Rule) bool {
	// Compare given needle to every item in haystack
	for _, url := range haystack {
		for _, rule := range rules {
			isEqual, match := needle.equals(url, rule)
			if (isEqual) {
				if verbose {
					log.Print("[+] Duplicate found!")
					log.Print("[+]     Omitting:     " + needle.Value)
					log.Print("[+]     Duplicate of: " + url.Value)
					log.Print("[+]     Per rule:     " + rule.Name + " (" + rule.Filepath + ")")
					if(match.isEquivalentURL) {
						log.Print("[+]          Strings are equivalent")
					}
					for key, element := range match.Tokens {
						log.Print("[+]          Matching " + key + ": " + element)
					}
					for _, element := range match.Inquisitors {
						if(len(element.KeyInquisitor) > 0){
							// Retrieve key/value of map[string]string
							for key, value := range element.KeyInquisitor {
								log.Print("[+]          Matching " + key + ": " + value)
							}
						}
						if(len(element.KeyValueInquisitor) > 0){
							// Retrieve key/value of map[string]bool
							for key, value := range element.KeyValueInquisitor {
								log.Print("[+]          Matching " + key + " (both are " + strconv.FormatBool(value) + ")")
							}
						}
					}
				}
				return true
			}
		}
	}
	return false
}

// Global flags.
var verbose bool
var insecure bool
var httpTimeout int

func batchQueryIPAddress(urls []*URL, size int) {
	maxBatchSize := size
	skip := 0
	numURLs := len(urls)
	numBatches := int(math.Ceil(float64(numURLs / maxBatchSize)))
	bar := progressbar.NewOptions(numURLs,
		progressbar.OptionSetDescription("Querying DNS A-Records..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
		// Need to print an extra newline to prevent clobbering the next line of output
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
	)

	for i := 0; i <= numBatches; i++ {
		lowerBound := skip
		upperBound := skip + maxBatchSize

		if upperBound > numURLs {
			upperBound = numURLs
		}

		batchItems := urls[lowerBound:upperBound]
		skip += maxBatchSize

		var itemProcessingGroup sync.WaitGroup
		itemProcessingGroup.Add(len(batchItems))

		for idx := 0; idx < len(batchItems); idx++ {
			bar.Add(1)
			go func(currentURL *URL) {
				// Mark WaitGroup as done at the end of this function.
				defer itemProcessingGroup.Done()
				// Process the URL: perform DNS query.
				if len(currentURL.IPAddrs) == 0 {
					currentURL.IPAddrs, _ = net.LookupIP(currentURL.Domain)
				}
			}(batchItems[idx])
		}
		itemProcessingGroup.Wait()

	}
}

// contentRegex: slice of regex strings to check.
func batchQueryHTTP(urls []*URL, size int, contentRegex []string, headerRegex []string) {
	maxBatchSize := size
	skip := 0
	numURLs := len(urls)
	numBatches := int(math.Ceil(float64(numURLs / maxBatchSize)))
	bar := progressbar.NewOptions(numURLs,
		progressbar.OptionSetDescription("Querying HTTP..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
		// Need to print an extra newline to prevent clobbering the next line of output
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
	)

	// Create HTTP client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(httpTimeout) * time.Second,
	}

	for i := 0; i <= numBatches; i++ {
		lowerBound := skip
		upperBound := skip + maxBatchSize

		if upperBound > numURLs {
			upperBound = numURLs
		}

		batchItems := urls[lowerBound:upperBound]
		skip += maxBatchSize

		var itemProcessingGroup sync.WaitGroup
		itemProcessingGroup.Add(len(batchItems))

		for idx := 0; idx < len(batchItems); idx++ {
			bar.Add(1)
			go func(currentURL *URL) {
				// Mark WaitGroup as done at the end of this function.
				defer itemProcessingGroup.Done()
				// Process the URL: perform HTTP query.
				if currentURL.StatusCode == 0 {
					resp, err := httpClient.Get(currentURL.Value)
					if err != nil {
						if verbose {
							log.Print("[+] HTTP Error: " + err.Error())
						}
					}
					if resp != nil {
						currentURL.StatusCode = resp.StatusCode
						currentURL.ContentLength = resp.ContentLength
						responseBody := StringifyResponseBody(resp)          // get the body as a string
						responseHeader := StringifyResponseHeader(resp)      // get the header as a string
						currentURL.ContentHash = CreateMD5Hash(responseBody) // calculate hash

						// populate content regex matches, if any:
						currentURL.ContentRegex = make(map[string]bool)
						for _, element := range contentRegex {
							regexMatch, err := regexp.MatchString(element,responseBody)
							if err != nil {
								fmt.Println("Bad regular expression: " + element)
							}
							currentURL.ContentRegex[element] = regexMatch
						}

						// populate header regex matches, if any:
						currentURL.HeaderRegex = make(map[string]bool)
						for _, element := range headerRegex {
							regexMatch, err := regexp.MatchString(element,responseHeader)
							if err != nil {
								fmt.Println("Bad regular expression: " + element)
							}
							currentURL.HeaderRegex[element] = regexMatch
						}
					}
				}
			}(batchItems[idx])
		}
		itemProcessingGroup.Wait()
	}

}

func batchQueryCNAME(urls []*URL, size int) {
	maxBatchSize := size
	skip := 0
	numURLs := len(urls)
	numBatches := int(math.Ceil(float64(numURLs / maxBatchSize)))
	bar := progressbar.NewOptions(numURLs,
		progressbar.OptionSetDescription("Querying DNS CNAME-Records..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWriter(os.Stderr),
		// Need to print an extra newline to prevent clobbering the next line of output
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
	)

	for i := 0; i <= numBatches; i++ {
		lowerBound := skip
		upperBound := skip + maxBatchSize

		if upperBound > numURLs {
			upperBound = numURLs
		}

		batchItems := urls[lowerBound:upperBound]
		skip += maxBatchSize

		var itemProcessingGroup sync.WaitGroup
		itemProcessingGroup.Add(len(batchItems))

		for idx := 0; idx < len(batchItems); idx++ {
			bar.Add(1)
			go func(currentURL *URL) {
				// Mark WaitGroup as done at the end of this function.
				defer itemProcessingGroup.Done()
				// Process the URL: perform DNS query.
				if currentURL.CName == "" {
					currentURL.CName, _ = net.LookupCNAME(currentURL.Domain)
				}
			}(batchItems[idx])
		}
		itemProcessingGroup.Wait()
	}
}

func StringifyResponseBody(response *http.Response) string {
	var responseBody string
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		if verbose {
			log.Print("[+] Response Read Error: " + err.Error())
		}
		return ""
	}
	responseBody = string(bodyBytes)
	return responseBody
}

// Unfortunately the net/http library gives us a header representation that is not original (due to parsing).
// The order and case of header field names are lost.
// HTTP/2 requests are dumped in HTTP/1.x form, not in their original binary representations.
// ref: https://pkg.go.dev/net/http/httputil#DumpResponse
func StringifyResponseHeader(response *http.Response) string {
	var responseHeader string
	headerBytes, err := httputil.DumpResponse(response, false)
	if err != nil {
		if verbose {
			log.Print("[+] Response Read Error: " + err.Error())
		}
		return ""
	}
	responseHeader = string(headerBytes)
	return responseHeader
}

func CreateMD5Hash(text string) string {
	var hashed_value string
	if len(text) > 0 {
		hasher := md5.New()
		hasher.Write([]byte(text))
		hashed_value = hex.EncodeToString(hasher.Sum(nil))
	}
	return hashed_value
}

// Determine whether a user passed a particular command line argument
func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {

	rulesFilepath := flag.String("rules", "", "Filepath for rule configuration")
	//ruleName := flag.String("rule", "*", "The single named rule to use (as defined in the rule configuration file)")
	numThreads := flag.Int("threads", 30, "Number of threads")
	flag.IntVar(&httpTimeout, "timeout", 3, "Timeout in seconds for HTTP requests")
	flag.BoolVar(&insecure, "insecure", false, "Disable TLS certificate verification")
	flag.BoolVar(&verbose, "verbose", false, "Increase verbosity in stderr")

	// Check for stdin data:
	stat, _ := os.Stdin.Stat()
	var inputIsStdIn bool
	var inputFilepath *string
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		inputIsStdIn = true
	} else {
		inputFilepath = flag.String("input", "input.txt", "Filepath for URL list. Overwritten by stdin.")
		inputIsStdIn = false
	}
	flag.Parse()

	// Set log flags. Available flags: https://pkg.go.dev/log#pkg-constants
	//log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetFlags(0)

	var cfg Config
	// Check if user supplies a rule file, else use default string match
	if isFlagPassed("rules") {
		// Parse configuration into struct
		rulesFile, err := ioutil.ReadFile(*rulesFilepath)
		if err != nil {
			fmt.Println(err)
		}

		err = yaml.Unmarshal(rulesFile, &cfg)
		if err != nil {
			fmt.Println(err)
		}

		// Populate filepath into each rule struct
		for i := 0; i < len(cfg.Rules); i++ {
			cfg.Rules[i].Filepath = *rulesFilepath
		}

	} else {
		// Set default rule configuration
		defaultRule := Rule{
			Name: "simple-string-match",
		}
		cfg = Config{Rules: []*Rule{&defaultRule}}
	}

	// Get the processor type
	//val := reflect.Indirect(reflect.ValueOf(rule.Processors[0]))
	//fmt.Println(val.Type().Field(0).Name)

	// Parse input file (or stdin) into array of URLs
	var urls []*URL
	var scanner *bufio.Scanner
	if inputIsStdIn {
		if verbose {
			log.Print("[+] Reading input from standard input...")
		}
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(*inputFilepath)
		if err != nil {
			fmt.Println(err)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}
	// Note: scanner limits lines to 64kb.
	for scanner.Scan() {
		urls = append(urls, parseURL(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}

	// Check whether to prepopulate Inquisitor-based URL attributes (fetch data only if the config rules need it)
	shouldPopulateDNSA := false
	shouldPopulateDNSCNAME := false
	shouldPopulateHTTP := false
	contentRegex := make([]string, 0)
	headerRegex := make([]string, 0)
	
	for _, rule := range cfg.Rules {
		for _, element := range rule.Inquisitors {
			// Review whether inquisitor is a Key (e.g., "dnsa")
			switch element.KeyInquisitor {
				case "dnsa":
					shouldPopulateDNSA = true
				case "dnscname":
					shouldPopulateDNSCNAME = true
				// If there's any of the http-get Inquisitors, populate them all from one query:
				case "statuscode", "contentlength", "contenthash":
					shouldPopulateHTTP = true
			}

			// Review whether inquisitor is a Key-Value (e.g., "contentregex: abcd")
			for key, value := range element.KeyValueInquisitor {
				switch key {
					case "contentregex":
						// Add regex to slice
						contentRegex = append(contentRegex, value)
						shouldPopulateHTTP = true
					case "headerregex":
						// Add regex to slice
						headerRegex = append(headerRegex, value)
						shouldPopulateHTTP = true
				}
			}
		}
	}
	
	// Perform queries if needed:
	if(shouldPopulateDNSA){
		batchQueryIPAddress(urls, *numThreads)
	}
	if(shouldPopulateDNSCNAME){
		batchQueryCNAME(urls, *numThreads)
	}
	if(shouldPopulateHTTP){
		batchQueryHTTP(urls, *numThreads, contentRegex, headerRegex)
	}

	// Get uniques
	var urlsUnique []*URL
	for _, element := range urls {
		if !existsWithin(element, urlsUnique, cfg.Rules) {
			urlsUnique = append(urlsUnique, element)
		} else {
			//fmt.Println("Not unique!")
		}
	}

	// Output results
	if verbose {
		log.Print("[+] Input list length:  " + fmt.Sprintf("%d", len(urls)))
		log.Print("[+] Output list length: " + fmt.Sprintf("%d", len(urlsUnique)))
		log.Print("[+] Printing list of unique URLs...")
	}
	for _, element := range urlsUnique {
		fmt.Println(element.Value)
	}
}
