cat << 'EOF' > README.md
# Certificate Expiry Checker (CS2106 — Project #12)

A command-line Bash utility that inspects SSL/TLS certificates for target domains, extracts their expiration timestamps, calculates remaining days relative to the current UTC time, flags expiring or expired certificates, and outputs results in a formatted table and optional CSV report[cite: 5].

## Overview & How It Works
1. **Input Parsing (`getopts` & File Reader):** Accepts domains via `-f <file>` (one domain per line, with `#` comments and blank lines ignored, and optional `host:port` syntax defaulting to port `443`) or as positional CLI arguments.
2. **TLS Handshake & Certificate Inspection:** Connects to each target host and port using `openssl s_client -servername "$host" -connect "${host}:${port}"` and extracts the `notAfter` expiration field using `openssl x509 -noout -enddate`[cite: 5].
3. **Date Normalization & Epoch Math:** Parses the extracted `notAfter` timestamp into Unix epoch seconds (`date -u -d` on Linux[cite: 5], with a `date -u -j -f` fallback for macOS), compares it against the current UTC epoch time (`date -u +%s`), and computes remaining days via `(( (expiry_epoch - now_epoch) / 86400 ))`.
4. **Status Classification & Reporting:** Classifies each certificate against the warning threshold (`-w`, default `30` days) and prints a readable table to standard output, optionally writing a CSV report with `-o <file.csv>`.

## Prerequisites
- `bash` (v3.2+ / v4+ / v5+)
- `openssl` (`s_client` and `x509` subcommands)[cite: 5]
- `date` (GNU `date` with `-d` on Linux[cite: 5]; BSD `date` with `-j -f` supported on macOS)
- Standard text utilities (`grep`, `sed`, `xargs`, `printf`)

## Usage Examples

### 1. Check domains listed in a file (default 30-day warning window)
```bash
./cert_expiry_checker.sh -f domains.txt
