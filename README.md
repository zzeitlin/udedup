# udedup
A modular URL deduplication tool.

### Installation
```
$ go get github.com/zzeitlin/udedup
```

### Usage
1. Define what you consider a "duplicate" URL
    1. This definition is declared in a `rules/*.yml` file
    1. For example: are two URLs that simply have the same scheme and domain equivalent? Do they also need to have the same path?
1. Provide an input list of URLs
1. Receive a deduplicated list of URLs.

```
$ udedup -h
Usage of udedup:
  -input string
        Filepath for list of URLs (default "input.txt")
  -insecure
        Disable TLS certificate verification
  -rules string
        Filepath for rule configuration (default "rules/default.yml")
  -verbose
        Increase verbosity in stderr
        
$ udedup -rules rules/default.yml -insecure -verbose -input input.txt
[+] Performing DNS A-Record queries...
[+] Duplicate found!
[+]     Omitting:     https://google.com
[+]     Duplicate of: https://www.google.com
[+]     Per rule:     simple (rules/default.yml)
[+] Duplicate found!
[+]     Omitting:     http://93.184.216.34
[+]     Duplicate of: http://example.com
[+]     Per rule:     simple (rules/default.yml)
[+] Input list length:  4
[+] Output list length: 2
[+] Printing list of unique URLs...
https://www.google.com
http://example.com

```

### Rule Definiton
See [rules/default.yml](rules/default.yml) for comments on the structure of defining equality.
