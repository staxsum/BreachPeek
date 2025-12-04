# BreachPeek

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)](https://github.com/moscovium-mc/BreachPeek/releases)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Tool Type](https://img.shields.io/badge/tool-OSINT-red.svg)]()
[![Built for](https://img.shields.io/badge/built%20for-security%20research-red.svg)]()

[![GitHub Stars](https://img.shields.io/github/stars/moscovium-mc/BreachPeek?style=social)](https://github.com/moscovium-mc/BreachPeek/stargazers)
[![Forks](https://img.shields.io/github/forks/moscovium-mc/BreachPeek?style=social)](https://github.com/moscovium-mc/BreachPeek/network/members)
[![Issues](https://img.shields.io/github/issues/moscovium-mc/BreachPeek)](https://github.com/moscovium-mc/BreachPeek/issues)

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/moscovium-mc/BreachPeek/graphs/commit-activity)
[![Last Commit](https://img.shields.io/github/last-commit/moscovium-mc/BreachPeek)](https://github.com/moscovium-mc/BreachPeek/commits/main)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Multi-source breach intelligence platform combining ProxyNova's 3.2B+ credential database with Have I Been Pwned's 570M+ password hashes and 928+ breach records. Built for offensive security research, penetration testing, and credential analysis.

## What it does

- **Multi-source intelligence** - ProxyNova (3.2B credentials) + HIBP (570M passwords + breach metadata)
- **Email:password search** - Query leaked credential combinations from ProxyNova
- **Password compromise checker** - Verify if passwords appear in known breaches (HIBP k-anonymity)
- **Breach intelligence** - Browse 928+ breach records with detailed metadata
- **Domain filtering** - Filter breaches by affected domain
- **Latest breach tracking** - Monitor newest additions to HIBP
- **Interactive CLI** - User-friendly command shell with auto-complete style
- **Type-safe architecture** - Full type hints and dataclasses throughout
- **Automatic retry logic** - Handles API failures with exponential backoff
- **Rate limiting protection** - Smart delays with jitter to avoid detection
- **No API key required** - HIBP password and breach APIs are completely free
- **Privacy-first** - K-anonymity makes sure passwords never leave your machine in full
- **Cross-platform** - Works on Windows, Linux, and macOS

## Getting it running

You'll need Python 3.7+. Install dependencies:
```bash
# Clone the repository
git clone https://github.com/moscovium-mc/BreachPeek.git
cd BreachPeek

# Install dependencies
pip install requests

# Run the tool
python3 breachpeek.py
```

## How to use it

**Interactive mode (recommended):**
```bash
python3 breachpeek.py
```

**CLI mode:**
```bash
python3 breachpeek.py search john@example.com
python3 breachpeek.py checkpw MyPassword123
python3 breachpeek.py breach Adobe
python3 breachpeek.py breaches linkedin.com
python3 breachpeek.py latest
```

## Commands

### ProxyNova - Credential Search

| Command | Description | Example |
|---------|-------------|---------|
| `search <query>` | Search email:password database | `search john@example.com` |
| `<email/username>` | Quick search (no command needed) | `john@example.com` |

### HIBP - Password Intelligence

| Command | Description | Example |
|---------|-------------|---------|
| `checkpw <password>` | Check if password is compromised | `checkpw Password123` |
| `pw <password>` | Quick password check | `pw MyP@ssw0rd` |

### HIBP - Breach Intelligence

| Command | Description | Example |
|---------|-------------|---------|
| `breaches` | List all breaches in HIBP | `breaches` |
| `breaches <domain>` | Filter breaches by domain | `breaches adobe.com` |
| `breach <name>` | Get detailed breach info | `breach Adobe` |
| `latest` | Show newest breach addition | `latest` |

### System

| Command | Description |
|---------|-------------|
| `help` | Show command reference |
| `clear` | Clear screen |
| `exit` / `quit` | Exit BreachPeek |

## Examples

### Check if your credentials were leaked
```bash
breach@peek » search john@example.com
[*] Searching ProxyNova for: john@example.com
[+] Found 156 results

#        EMAIL/USERNAME                                PASSWORD
--------------------------------------------------------------------------------
1        john@example.com                              password123
2        john@example.com                              qwerty2020
```

### Verify password safety
```bash
breach@peek » checkpw password123
[*] Querying HIBP...
[!!!] COMPROMISED [!!!]
[!] Seen 3,861,493 times in breaches
[!] Change this password immediately on all accounts
```

### List all breaches
```bash
breach@peek » breaches
[*] Fetching all HIBP breaches...
[+] Found 928 breaches

BREACH                         DOMAIN                    PWN COUNT          DATE
-------------------------------------------------------------------------------------
Collection #1                  -                       772,904,991       2019-01-16
LinkedIn                       linkedin.com            164,611,595       2012-05-05
Adobe                          adobe.com               152,445,165       2013-10-04
```

### Get breach details
```bash
breach@peek » breach Adobe
[*] Fetching: Adobe
================================================================================
Adobe
================================================================================
Domain: adobe.com
Breach Date: 2013-10-04
Added to HIBP: 2013-12-04T00:00:00Z
Pwn Count: 152,445,165 accounts
Data Classes: Email addresses, Password hints, Passwords, Usernames
Flags: [VERIFIED]

In October 2013, 153 million Adobe accounts were breached with each containing 
an internal ID, username, email, encrypted password and a password hint in plain 
text. The password cryptography was poorly done and many were quickly resolved 
back to plain text...
================================================================================
```

### Filter breaches by domain
```bash
breach@peek » breaches linkedin.com
[*] Fetching breaches for: linkedin.com
[+] Found 3 breaches

BREACH                         DOMAIN                    PWN COUNT          DATE
-------------------------------------------------------------------------------------
LinkedIn                       linkedin.com            164,611,595       2012-05-05
```

## Output Examples

### Password Check - Safe
```
[*] Querying HIBP...
[✓] Not found in HIBP database
    Note: Absence doesn't guarantee strength
```

### Password Check - Compromised
```
[*] Querying HIBP...
[!!!] COMPROMISED [!!!]
[!] Seen 3,861,493 times in breaches
[!] Change this password immediately on all accounts
```

### Credential Search Results
```
#        EMAIL/USERNAME                                PASSWORD
--------------------------------------------------------------------------------
1        john@example.com                              password123
2        john@example.com                              qwerty2020
3        john.doe@example.com                          welcome123
```

## Known Limitations

### ProxyNova Pagination
ProxyNova's API may return `400 Bad Request` errors when paginating beyond the first 100 results. This is an **API-side limitation**, not a bug in BreachPeek.

**What happens:**
- First 100 results: Always works reliably
- Beyond 100 results: May be blocked by ProxyNova's rate limiting

**Why this happens:**
ProxyNova implements aggressive rate limiting to prevent abuse. The tool automatically retries with exponential backoff (3 attempts), but persistent blocks are expected.

**Workarounds:**
1. Use more specific search queries (e.g., full email addresses instead of usernames)
2. Wait 5-10 minutes between large searches
3. The tool will ask if you want to continue after failed retries

### HIBP Free Tier
- Password compromise checking: **Free, unlimited**
- Breach metadata: **Free, unlimited**
- Email breach searches: **Requires paid API key** (not implemented in v2.0)

See [HIBP Pricing](https://haveibeenpwned.com/API/Key) for details on email search capabilities.

## Fully Working Features

- ProxyNova credential search (first 100 results guaranteed)
- HIBP password compromise checking (k-anonymity, privacy-safe)
- HIBP breach listing (928+ breaches)
- HIBP breach details with full metadata
- Domain-filtered breach searches
- Latest breach tracking
- Automatic retry logic with exponential backoff
- Rate limiting protection
- Cross-platform support (Windows/Linux/macOS)

## Version History

### v2.0.0 (Current)

**Complete Rewrite:**
- Multi-source architecture combining ProxyNova + HIBP
- HIBP password compromise checker (570M+ passwords)
- HIBP breach intelligence (928+ breaches with metadata)
- Domain-filtered breach searches
- Latest breach tracking

**Technical Improvements:**
- Complete rewrite with object-oriented architecture
- Type hints throughout the codebase (PEP 484)
- Dataclasses for structured data handling (`PasswordCheckResult`, `BreachRecord`, `ProxyNovaResult`)
- Better error handling with custom exceptions (`APIError`, `APITimeoutError`, `RateLimitError`)
- Automatic retry logic with exponential backoff (3 attempts)
- Smart rate limiting with random jitter to avoid detection
- Cleaner resource cleanup (signal handlers for SIGINT/SIGTERM)
- Persistent HTTP sessions for better performance
- Separated concerns (API clients, display logic, CLI controller)

**User Experience:**
- Redesigned CLI
- Interactive command shell (`breach@peek »`)
- Clear error messages and retry feedback
- Progress indicators during API calls
- Automatic pagination with user control
- Help system with examples

**Known Issues:**
- ProxyNova API blocks pagination after ~100 results (API limitation, not a bug)
- Tool handles this nicely with retry logic and user prompts

### v1.5.0

**Initial Release:**
- ProxyNova credential search (3.2B+ records)
- Interactive CLI with search, help, clear commands
- Basic error handling
- Rate limiting (100 requests/minute)
- Cross-platform support

## Platform Support

### Tested On
- **Windows 10/11**: Fully functional (Command Prompt, PowerShell, Windows Terminal)
- **Linux (Ubuntu/Debian/Kali)**: Fully functional
- **macOS**: Fully functional (Python 3.7+)

### Requirements
- Python 3.7 or higher
- `requests` library

## API Details

**ProxyNova:**
- Endpoint: `https://api.proxynova.com/comb`
- Rate Limit: ~100 requests per minute
- Data: 3.2B+ credentials from public breaches
- Authentication: None required

**Have I Been Pwned:**
- Password API: `https://api.pwnedpasswords.com/range`
- Breach API: `https://haveibeenpwned.com/api/v3`
- Rate Limit: None for password/breach APIs
- Authentication: None required for implemented features
- Privacy: k-anonymity model (only sends first 5 chars of password hash)

## Contributing

Got ideas for improvements? Found a bug? Contributions are welcome:

- Bug reports and fixes
- New features (additional data sources, export formats, etc.)
- Documentation improvements
- UI/UX enhancements

**Please make sure contributions maintain:**
- Ethical security research standards
- Legal compliance
- Code quality (type hints, docstrings)
- Responsible disclosure practices

## Support

If you find this project useful, consider supporting my work:

<a href="https://buymeacoffee.com/webmoney" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="40"></a>

**Crypto donations:**
- <a href="bitcoin:bc1quavqz6cxqzfy4qtvq4zxc4fjgap3s7cmxja0k4"><img src="https://img.shields.io/badge/Bitcoin-000000?style=plastic&logo=bitcoin&logoColor=white" alt="Bitcoin"></a> `bc1quavqz6cxqzfy4qtvq4zxc4fjgap3s7cmxja0k4`
- <a href="ethereum:0x5287af72afbc152b09b3bf20af3693157db9e425"><img src="https://img.shields.io/badge/Ethereum-627EEA?style=plastic&logo=ethereum&logoColor=white" alt="Ethereum"></a> `0x5287af72afbc152b09b3bf20af3693157db9e425`
- <a href="solana:HYZjfEx8NbEMJX1vL1GmGj39zA6TgMsHm5KCHWSZxF4j"><img src="https://img.shields.io/badge/Solana-9945FF?style=plastic&logo=solana&logoColor=white" alt="Solana"></a> `HYZjfEx8NbEMJX1vL1GmGj39zA6TgMsHm5KCHWSZxF4j`
- <a href="monero:86zv6vTDuG35sdBzBpwVAsD71hbt2gjH14qiesyrSsMkUAWHQkPZyY9TreeQ5dXRuP57yitP4Yn13SQEcMK4MhtwFzPoRR1"><img src="https://img.shields.io/badge/Monero-FF6600?style=plastic&logo=monero&logoColor=white" alt="Monero"></a> `86zv6vTDuG35sdBzBpwVAsD71hbt2gjH14qiesyrSsMkUAWHQkPZyY9TreeQ5dXRuP57yitP4Yn13SQEcMK4MhtwFzPoRR1`

## Important Legal Stuff

**READ THIS BEFORE USING**

**This tool is for authorized security research ONLY.**

By using BreachPeek, you acknowledge that:

1. **Authorized Use Only:**
   - You will only check your own credentials
   - You have explicit written authorization for any other credentials checked
   - You are conducting authorized security research or penetration testing

2. **Prohibited Activities:**
   - Credential stuffing attacks
   - Unauthorized account access
   - Using discovered credentials without permission
   - Any malicious or illegal activities

3. **Legal Compliance:**
   - You will comply with all applicable laws including CFAA (18 U.S.C. § 1030)
   - You will comply with GDPR and other data protection regulations
   - You understand that unauthorized access to computer systems is a crime

4. **Liability:**
   - The author provides NO WARRANTIES and accepts NO LIABILITY for misuse
   - Users assume ALL RESPONSIBILITY for their actions
   - This tool is provided "AS IS" without warranty of any kind

**Unauthorized access to computer systems is illegal. If you don't have permission, don't use this tool.**

## Responsible Use Guidelines

If you discover exposed credentials:

**DO:**
- Notify affected parties through proper disclosure channels
- Recommend password changes and 2FA enablement
- Handle sensitive information with appropriate care
- Document findings for authorized security assessments

**DON'T:**
- Attempt to access accounts without authorization
- Share credentials publicly
- Use credentials for personal gain
- Perform any unauthorized activities

## Ethical Considerations

This tool exists to:
- Help people check if their own credentials are compromised
- Support authorized penetration testing engagements
- Demonstrate the importance of unique passwords and 2FA
- Contribute to improved security practices

Use it responsibly. Security research should make the internet safer, not more dangerous.

## License

MIT License - See LICENSE file for details.

**Use responsibly. Unauthorized access to computer systems is illegal.**

---

**Disclaimer:** BreachPeek is a security research tool. The developers are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security research.
