# ADS Memory Forensics

macOS Memory Forensics Tool - Part of the ADS macOS Security Suite.

## Features

- **Memory Dump**: Dump process memory regions for offline analysis
- **Memory Scan**: Scan for secrets, injection, and suspicious strings
- **Region Listing**: View all memory regions with protection flags
- **YARA Support**: Match memory against YARA rules
- **JSON Output**: Machine-readable output for automation
- **HTTP API**: Server mode for GUI console integration

## Installation

```bash
make build
sudo make install
```

**Note**: This tool requires root privileges for memory access on macOS.

## Usage

### List Memory Regions

```bash
# List regions for a process
ads-memory-forensics regions --pid 1234

# JSON output
ads-memory-forensics regions --pid 1234 --output-json
```

### Scan Process Memory

```bash
# Full scan
sudo ads-memory-forensics scan --pid 1234

# Scan for secrets only
sudo ads-memory-forensics scan --pid 1234 --secrets

# Scan for code injection
sudo ads-memory-forensics scan --pid 1234 --injection

# Extract suspicious strings
sudo ads-memory-forensics scan --pid 1234 --strings

# YARA rule matching
sudo ads-memory-forensics scan --pid 1234 --yara rules.yar
```

### Dump Process Memory

```bash
# Dump to file
sudo ads-memory-forensics dump --pid 1234 --output /tmp/dump.bin

# Dump all regions (including non-readable)
sudo ads-memory-forensics dump --pid 1234 --output /tmp/dump.bin --all
```

### HTTP API Server

```bash
# Start server on default port (9002)
sudo ads-memory-forensics serve

# Custom port
sudo ads-memory-forensics serve --port 8080
```

#### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | Tool version and capabilities |
| `/regions?pid=N` | GET | List memory regions |
| `/scan` | POST | Scan process memory |
| `/dump` | POST | Dump process memory |

## Detection Capabilities

### Secrets Detection

| Type | Pattern | Description |
|------|---------|-------------|
| AWS Access Key | `AKIA...` | AWS access key ID |
| AWS Secret | `aws_secret_access_key` | AWS secret key |
| GitHub Token | `ghp_`, `gho_` | GitHub personal/OAuth tokens |
| API Key | `sk-` | Generic API keys (OpenAI, etc.) |
| Bearer Token | `Bearer ` | OAuth bearer tokens |
| Basic Auth | `Basic ` | Base64 encoded credentials |
| Private Key | `-----BEGIN` | PEM private keys |
| Password | `password=`, `passwd=` | Password in config |

### Injection Detection

| Type | Description |
|------|-------------|
| NOP Sled | Long sequences of 0x90 (x86 NOP) |
| Syscall | Direct syscall instructions |
| Shellcode | Common shellcode patterns |
| ROP Gadgets | Return-oriented programming chains |

### String Extraction

Extracts strings containing:
- URLs (http://, https://)
- Shell paths (/bin/sh, /bin/bash)
- Network tools (curl, wget, nc)
- Encoding commands (base64, eval)

## Threat Score

The scan produces a threat score (0-100) based on:
- Secrets found: +15 per secret
- Injection indicators: +25 per indicator
- Suspicious strings: +5 per string
- YARA matches: +20 per match

## Integration

This tool integrates with:

1. **ADS Security Console GUI** - via HTTP API on port 9002
2. **afterdark-darkd** - as a service plugin
3. **SIEM/SOAR** - via JSON output

```bash
# Part of the ADS Security Suite
ads-process-monitor serve --port 9001   # Process visibility
ads-memory-forensics serve --port 9002  # Memory analysis
ads-supply-chain serve --port 9003      # Package monitoring
```

## Requirements

- macOS 10.15+ (Catalina or later)
- Root privileges (sudo)
- CGO enabled (for Mach API access)

## License

Copyright (c) 2026 After Dark Systems. All rights reserved.
