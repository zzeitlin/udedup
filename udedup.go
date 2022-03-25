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
	"net/url"
	"os"
	"sync"
	"time"
	"strconv"
	"strings"

	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"
)

// https://zhwt.github.io/yaml-to-go/
//type Config struct {
//	Rules []struct {
//		Name			 string	 `yaml:"name"`
//		Tokens		 []string `yaml:"tokens"`
//		Processors []struct {
//			Urlencode		string `yaml:"urlencode,omitempty"`
//			Base64Encode string `yaml:"base64encode,omitempty"`
//		} `yaml:"processors"`
//		Inquisitors []string `yaml:"inquisitors"`
//	} `yaml:"rules"`
//}

type Config struct {
	Rules []*Rule `yaml:"rules"`
}
type Rule struct {
	Name        string `yaml:"name"`
	Filepath    string
	Tokens      []string     `yaml:"tokens"`
	Processors  []*Processor `yaml:"processors"`
	Inquisitors []string     `yaml:"inquisitors"`
}
// A Match is used to record the actual values obtained that lead to two URLs being declared duplicate.
type Match struct{
	isEquivalentURL bool
	Tokens map[string]string
	Inquisitors map[string]string
}
type Processor struct {
	Urlencode    string `yaml:"urlencode,omitempty"`
	Base64Encode string `yaml:"base64encode,omitempty"`
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

	// Example tokens: port, path, fragment, queryparams, ...
	Tokens map[string]string
}

// Equality between two URLs depends on the Rule struct
func (u *URL) equals(u2 *URL, rule *Rule) (bool, Match) {
	// Initialize empty return match
	match := Match{}
	match.Tokens = make(map[string]string)
	match.Inquisitors = make(map[string]string)

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
		switch element {
		case "dnsa":
			matchExists := false
			for _, uIP := range u.IPAddrs {
				for _, u2IP := range u2.IPAddrs {
					if uIP.Equal(u2IP) {
						match.Inquisitors[element] = uIP.String()
						matchExists = true
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
				match.Inquisitors[element] = u.CName
			}
		case "statuscode":
			if u.StatusCode != u2.StatusCode {
				return false, match
			} else {
				match.Inquisitors[element] = strconv.Itoa(u.StatusCode)
			}

		case "contentlength":
			if u.ContentLength != u2.ContentLength {
				return false, match
			} else {
				match.Inquisitors[element] = strconv.FormatInt(u.ContentLength, 10)
			}
		case "contenthash":
			if u.ContentHash != u2.ContentHash {
				return false, match
			} else {
				match.Inquisitors[element] = u.ContentHash
			}
		default:
			fmt.Println("Unknown Inquisitor: " + element)
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
						log.Print("[+]     Strings are equivalent")
					}
					for key, element := range match.Tokens {
						log.Print("[+]          " + key + ": " + element)
					}
					for key, element := range match.Inquisitors {
						log.Print("[+]          " + key + ": " + element)
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

func batchQueryHTTP(urls []*URL, size int) {
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
						currentURL.ContentHash = CreateMD5Hash(responseBody) // lets hash this thing
					}
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

func CreateMD5Hash(text string) string {
	var hashed_value string
	if len(text) > 0 {
		hasher := md5.New()
		hasher.Write([]byte(text))
		hashed_value = hex.EncodeToString(hasher.Sum(nil))
	}
	return hashed_value
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
	//cTimeout := flag.Int("timeout", 5, "Connection timeout in seconds")

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

	// Prepopulate Inquisitor-based URL attributes (fetch data only if the config rules need it)
	// Booleans used to save whether URL struct has populated the data (to prevent multiple fetches)
	isPopulatedDNSA := false
	isPopulatedDNSCNAME := false
	isPopulatedSCCL := false

	for _, rule := range cfg.Rules {
		for _, element := range rule.Inquisitors {
			switch element {
			case "dnsa":
				if !isPopulatedDNSA {
					batchQueryIPAddress(urls, *numThreads)

				}
				isPopulatedDNSA = true
			case "dnscname":
				if !isPopulatedDNSCNAME {
					batchQueryCNAME(urls, *numThreads)
				}
				isPopulatedDNSCNAME = true
			// If there's any of the http-get Inquisitors, populate them all from one query:
			case "statuscode", "contentlength", "contenthash":
				if !isPopulatedSCCL {
					batchQueryHTTP(urls, *numThreads)
				}
				isPopulatedSCCL = true
			}
		}
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
