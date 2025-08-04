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

## Real-world Use Cases

**S3X is designed for legitimate security testing and research purposes:**

- **Penetration Testing**: Identify vulnerabilities during authorized security assessments
- **Bug Bounty Hunting**: Discover security issues in scope targets for responsible disclosure
- **Security Audits**: Assess infrastructure misconfigurations in corporate environments
- **Red Team Exercises**: Simulate real-world attacks for defensive training
- **Educational Research**: Learn about security vulnerabilities and attack vectors
- **Infrastructure Monitoring**: Regular scans to ensure security posture compliance

## Contribution Guidelines

We welcome contributions to S3X! Here's how you can help:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** and test thoroughly
4. **Follow our coding standards**:
   - Use meaningful variable names
   - Add comments for complex logic
   - Follow PEP 8 style guidelines
5. **Commit your changes**: `git commit -m 'Add new feature'`
6. **Push to your branch**: `git push origin feature-name`
7. **Submit a Pull Request** with a clear description

### What We're Looking For

- **New scanning modules** for different services/protocols
- **Bug fixes** and performance improvements
- **Documentation improvements**
- **Test cases** and quality assurance
- **Feature enhancements** and usability improvements

### Code Review Process

- All contributions will be reviewed by maintainers
- We may request changes or improvements
- Once approved, changes will be merged into the main branch

## Credits / Acknowledgments

**S3X Security Suite X** is built on the shoulders of giants. We acknowledge:

### Core Libraries
- **requests** - HTTP library for Python
- **asyncio** - Asynchronous I/O support
- **ssl** - SSL/TLS wrapper for socket objects
- **socket** - Low-level networking interface
- **dns.resolver** - DNS resolution library
- **jwt** - JSON Web Token implementation

### Security Research Community
- **OWASP** - Open Web Application Security Project
- **Shodan** - Internet-connected device search engine
- **VirusTotal** - File and URL analysis service
- **Have I Been Pwned** - Breach notification service

### Special Thanks
- **Security researchers** who inspire better tooling
- **Open source contributors** who make security accessible
- **The Python community** for excellent libraries and support

## Disclaimer

⚠️ **IMPORTANT: Legal and Ethical Use Only** ⚠️

**S3X Security Suite X** is designed for **legitimate security testing purposes only**. By using this tool, you agree to the following:

### ✅ Authorized Use
- **Only scan systems you own** or have explicit written permission to test
- **Respect scope limitations** in penetration testing engagements
- **Follow responsible disclosure** practices for discovered vulnerabilities
- **Comply with local laws** and regulations regarding security testing

### ❌ Prohibited Use
- **Do NOT** use this tool for unauthorized access to systems
- **Do NOT** use this tool for malicious purposes or illegal activities
- **Do NOT** scan systems without proper authorization
- **Do NOT** use results to harm individuals or organizations

### Legal Responsibility
- **Users are solely responsible** for ensuring lawful use of this tool
- **We disclaim any liability** for misuse or illegal activities
- **Always obtain proper authorization** before conducting security tests
- **Report vulnerabilities responsibly** through appropriate channels

### Educational Purpose
This tool is provided for **educational and research purposes** to help improve cybersecurity awareness and defensive capabilities.

**Remember: With great power comes great responsibility. Use S3X ethically and responsibly.**

## License

This project is licensed under the MIT License.
