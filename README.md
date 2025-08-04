# S3X - Security Suite X

**Made by Decimal & Vectorindia01 By Team H4$HCR4Ck**

S3X (Security Suite X) is a comprehensive, lightweight Python-based security tool designed to detect and exploit common infrastructure misconfigurations. Built for efficiency and versatility, it targets vulnerabilities across various platforms.

## Features

- **S3 Bucket Scanning**
- **FTP Service Analysis**
- **JWT Security Checks**
- **Subdomain Enumeration**
- **Advanced Port Scanning**
- **SSL/TLS Security Analysis**
- **Integration with VirusTotal**
- **Developers and Debug Endpoints Detection**
- **Dorking and External Reconnaissance**

## Installation

### Prerequisites

- **Python 3.7 or higher**
- **pip**

### Steps

1. Clone the repository:

    ```sh
    git clone https://github.com/yfwmaniish/S3X-Security-Suite-X.git
    cd S3X-Security-Suite-X
    ```

2. Install the necessary packages:

    ```sh
    pip install -r requirements.txt
    ```

## Usage

Run S3X using Python:

```sh
python s3x.py --target example.com --all
```

### Options:

- `--target`: Target to scan (IP, domain, URL, or S3 bucket name)
- `--jwt`: JWT token to analyze
- `--all`: Run all available scans (requires target)
- Specific modules such as `--s3`, `--subdomain`, `--ssl`
- `--api-key`: Provide API key directly for services
- `--verbose`: Enable detailed output
- `--quiet`: Suppress non-essential output

## Contribution Guide

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes
4. Commit those changes (`git commit -m 'Description of changes'`)
5. Push to your branch (`git push origin feature-branch`)
6. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# S3X - Security Suite X

**Made by S3X Team**

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
$ git clone https://github.com/yfwmaniish/s3x.git
$ cd s3x
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
