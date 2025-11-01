# BreachPeek

A CLI tool for searching leaked credential databases. Intended for authorized security research and credential monitoring.

## Warning

This tool is for authorized security research only. Using this tool to access accounts without permission is illegal. See the legal section below before using.

## What it does

BreachPeek searches through aggregated breach data (3.2B+ records) to check if credentials have been compromised in known data breaches. It uses API calls and displays results through an CLI.

## Requirements

- Python 3.6 or higher
- `requests` library

## Installation
```bash
download or clone this repo
cd breachpeek
python3 -m pip install requests
```

## Usage

Run:
```bash
python3 breachpeek.py
```

Search directly:
```bash
python3 breachpeek.py john@example.com
python3 breachpeek.py -l 50 username123
```

Available commands:
- `help` - Show help information
- `clear` - Clear screen
- `exit` or `quit` - Exit program

## Legal Notice

**READ THIS BEFORE USING**

This software is provided for educational and authorized security research purposes only.

By using this tool, you acknowledge that:

1. You will only use it in compliance with applicable laws, including but not limited to the Computer Fraud and Abuse Act (18 U.S.C. § 1030), GDPR, and local computer crime statutes.

2. You will only check:
   - Your own credentials
   - Credentials you have explicit written authorization to research
   - Organizational credentials as part of authorized security assessments

3. You will NOT:
   - Access accounts without authorization
   - Perform credential stuffing attacks
   - Use discovered credentials for unauthorized access
   - Engage in any malicious activities

4. The author provides no warranties and accepts no liability for misuse of this tool. Users assume all responsibility for their actions.

Unauthorized access to computer systems is a crime. If you don't have authorization, don't use this tool.

## Responsible Use

If you discover exposed credentials:
- Do not attempt to access the accounts
- Notify affected parties through proper channels
- Recommend password changes and 2FA
- Handle sensitive information appropriately

## API Details

- Source: ProxyNova Combined Query API
- Rate Limit: Approximately 100 requests per minute
- Data: Aggregated from publicly disclosed breaches
- Storage: No credentials are stored locally by this tool

## Contributing

Pull requests should maintain ethical security research standards and legal compliance. Update documentation to reflect any changes.

## License

Educational and authorized security research use only. See LICENSE file.

---

Use responsibly. Unauthorized access to computer systems is illegal.
