# S3X - Security Suite X

**Made by Decimal & Vectorindia01 By Team H4$HCR4Ck**

S3X (Security Suite X) is a powerful and lightweight Python-based security tool designed to detect and exploit common infrastructure misconfigurations.

## Features

- Scan for publicly accessible S3 buckets
- Check for open/anonymous FTP services
- Identify exposed development/debug endpoints
- Analyze JWT tokens for vulnerabilities
- Perform external reconnaissance using Shodan
- Enumerate subdomains
- Advanced port scanning with service and vulnerability detection
- In-depth SSL/TLS analysis
- Integration with VirusTotal and Have I Been Pwned
- Directory and file brute forcing with custom wordlists
- HTTP cookie security analysis (Secure, HttpOnly, SameSite flags)
- Generate detailed HTML and PDF reports

## Installation

1. Clone the repository:

```sh
$ git clone https://github.com/yfwmaniish/S3X-Security-Suite-X.git
$ cd S3X-Security-Suite-X
```

2. Install the dependencies:

```sh
$ pip install -r requirements.txt
```

## Usage

Run S3X using Python:

```sh
$ python s3x.py --target example.com --all
```

### Options:

- `--target`: Target to scan (IP, domain, URL, or S3 bucket name)
- `--jwt`: JWT token to analyze
- `--all`: Run all available scans (requires target)
- `--s3`, `--s3-bucket`, `--ftp`, `--dev`, `--shodan`, `--subdomain`, `--port-scan`, `--ssl`, `--virustotal`, `--hibp`, `--dir-bruteforce`, `--cookie-security`: Specific modules to run
- `--api-key`: Shodan API key (or set `SHODAN_API_KEY` env var)
- `--wordlist`: Custom wordlist for dev endpoint scanning
- `--timeout`: Request timeout in seconds
- `--threads`: Number of concurrent threads
- `--output`: Save results to file
- `--json`: Output results in JSON format
- `--auto-report`: Automatically generate a report after the scan
- `--report-format`: Report format (html, pdf, both)
- `--verbose`: Enable verbose output
- `--quiet`: Suppress banner and non-essential output

## License

This project is licensed under the MIT License.
