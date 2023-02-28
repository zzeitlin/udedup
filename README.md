# udedup
A modular URL deduplication tool.

### Installation

> Using Go version 1.17 or higher:
```
$ go install github.com/zzeitlin/udedup@latest
```

> Using Go versions older than 1.17:
```
$ go get github.com/zzeitlin/udedup
```

### Usage
1. Define what you consider a "duplicate" URL
    1. This definition is declared in a `rules/*.yml` file
    1. For example: are two URLs that simply have the same scheme and domain equivalent? Do they also need to have the same path?
1. Provide an input list of URLs
1. Receive a deduplicated list of URLs.

```bash
# Review help menu:
$ udedup -h
Usage of udedup:
  -input string
    	Filepath for URL list. Overwritten by stdin. (default "input.txt")
  -insecure
    	Disable TLS certificate verification
  -rules string
    	Filepath for rule configuration
  -threads int
    	Number of threads (default 30)
  -timeout int
    	Timeout of HTTP requests (default 3)
  -verbose
    	Increase verbosity in stderr

# Basic example using standard input in a pipeline:
$ cat input.txt | go run udedup.go -rules rules/example.yml -insecure
Querying DNS A-Records... 100% |████████████████████████████████████████| (6/6)
https://www.google.com
http://google.com
http://example.com

# Basic verbose example using an input file:
$ udedup -input input.txt -rules rules/example.yml -insecure -verbose
Querying DNS A-Records... 100% |████████████████████████████████████████| (6/6)
[+] Duplicate found!
[+]     Omitting:     https://google.com
[+]     Duplicate of: https://www.google.com
[+]     Per rule:     simple (rules/example.yml)
[+]          Matching scheme: https
[+]          Matching port: 443
[+]          Matching path: /
[+]          Matching dnsa: 216.239.38.120
[+] Duplicate found!
[+]     Omitting:     http://93.184.216.34
[+]     Duplicate of: http://example.com
[+]     Per rule:     simple (rules/example.yml)
[+]          Matching scheme: http
[+]          Matching port: 80
[+]          Matching path: /
[+]          Matching dnsa: 93.184.216.34
[+] Duplicate found!
[+]     Omitting:     http://example.com
[+]     Duplicate of: http://example.com
[+]     Per rule:     default (rules/example.yml)
[+]     Strings are equivalent
[+] Input list length:  6
[+] Output list length: 3
[+] Printing list of unique URLs...
https://www.google.com
http://google.com
http://example.com
```

### Rule Definiton
See [rules/example.yml](rules/example.yml) for comments on the structure of defining equality.
