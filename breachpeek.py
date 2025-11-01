#!/usr/bin/env python3
"""
BreachPeek - Security Research At Scale
Search the world's largest dataset of leaked passwords

Author: stax
DISCLAIMER: For authorized security research only. Unauthorized access to systems or accounts is illegal. This software is provided "AS IS" without warranty. Users assume all responsibility and agree to use only for their own credentials or with explicit authorization. The author is not liable for any damages or misuse. Users must comply with all applicable laws including CFAA 18 U.S.C. § 1030 and GDPR. By using this software you agree to these terms.
"""

import requests
import argparse
import sys
import time
from urllib.parse import quote
import os

API_URL = 'https://api.proxynova.com/comb'
DEFAULT_LIMIT = 100  # Max results per request (API max)
MAX_LIMIT = 100
RATE_LIMIT_DELAY = 0.6  # 100 requests per minute

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_banner():
    """Display the CLI banner"""
    banner = f"""{CYAN}
______     ______     ______     ______     ______     __  __     ______   ______     ______     __  __    
/\\  == \\   /\\  == \\   /\\  ___\\   /\\  __ \\   /\\  ___\\   /\\ \\_\\ \\   /\\  == \\ /\\  ___\\   /\\  ___\\   /\\ \\/ /    
\\ \\  __<   \\ \\  __<   \\ \\  __\\   \\ \\  __ \\  \\ \\ \\____  \\ \\  __ \\  \\ \\  _-/ \\ \\  __\\   \\ \\  __\\   \\ \\  _"-.  
 \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_\\    \\ \\_____\\  \\ \\_____\\  \\ \\_\\ \\_\\ 
  \\/_____/   \\/_/ /_/   \\/_____/   \\/_/\\/_/   \\/_____/   \\/_/\\/_/   \\/_/     \\/_____/   \\/_____/   \\/_/\\/_/ 
                                                                                                            
{GREEN}Breach Database Search - 3.2B+ Leaked Credentials{RESET}
{YELLOW}Security Research At Scale{RESET}
"""
    print(banner)


def check_api_status():
    """Check if the API is online and returning valid data"""
    test_url = f"{API_URL}?query=test&start=0&limit=1"
    try:
        response = requests.get(test_url, timeout=5)
        # Check HTTP status
        if response.status_code != 200:
            return False, f"HTTP {response.status_code}"

        # Check JSON validity
        data = response.json()
        if not isinstance(data, dict):
            return False, "Invalid JSON structure"

        # Check for expected keys
        if 'count' not in data or 'lines' not in data:
            return False, "Missing expected keys in response"

        return True, "Online and responding correctly"

    except requests.exceptions.Timeout:
        return False, "Timeout"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {e}"
    except ValueError:
        return False, "Invalid JSON response"


def print_help():
    """Display help information"""
    help_text = f"""
{BOLD}Available Commands:{RESET}
  {GREEN}<email/username>{RESET}     - Search for credentials (just type the query directly!)
  {GREEN}help{RESET}                  - Show this help message
  {GREEN}exit / quit{RESET}           - Exit the program
  {GREEN}clear{RESET}                 - Clear the screen

{BOLD}Examples:{RESET}
  john@example.com
  jrubin
  user123

{BOLD}Options (when using search):{RESET}
  You'll be prompted to load more results after each batch.
  Press 'y' to continue or 'n' to stop.
  Default: 100 results per page (API max)

{BOLD}Tips:{RESET}
  • If your credentials are found, change your password immediately!
  • Always enable two-factor authentication (2FA) when possible.
  • Use unique passwords for each service.
"""
    print(help_text)


def search_credentials(query, start=0, limit=DEFAULT_LIMIT):
    """Search for credentials in the database"""
    limit = min(limit, MAX_LIMIT)
    request_url = f"{API_URL}?query={quote(query)}&start={start}&limit={limit}"

    try:
        if start > 0:
            time.sleep(RATE_LIMIT_DELAY)

        response = requests.get(request_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{RED}[ERROR] Failed to fetch data: {e}{RESET}")
        return None


def display_results(data, start_index):
    """Display search results in a formatted table"""
    if not data or data.get('count', 0) == 0:
        print(f"{YELLOW}[INFO] No results found.{RESET}")
        return False

    lines = data.get('lines', [])
    if not lines:
        print(f"{YELLOW}[INFO] No more results available.{RESET}")
        return False

    print(f"\n{BOLD}{'Index':<8} {'Username/Email':<40} {'Password':<30}{RESET}")
    print("-" * 80)

    for i, line in enumerate(lines, start=start_index + 1):
        parts = line.split(':', 1)
        username = parts[0] if len(parts) > 0 else 'N/A'
        password = parts[1] if len(parts) > 1 else 'N/A'
        print(f"{i:<8} {username:<40} {password:<30}")

    return True


def perform_search(query):
    """Perform a search with pagination"""
    start = 0
    limit = DEFAULT_LIMIT

    print(f"\n{CYAN}[*] Searching for: {query}{RESET}")

    # Search
    data = search_credentials(query, start, limit)
    if not data:
        return

    total_count = data.get('count', 0)
    print(f"{GREEN}[+] Found {total_count} total results{RESET}")

    if not display_results(data, start):
        return

    start += limit

    # loop
    while start < total_count:
        print(f"\n{CYAN}[*] Showing results {start}/{total_count}{RESET}")
        user_input = input(f"{YELLOW}Load more results? (y/n): {RESET}").strip().lower()

        if user_input != 'y':
            print(f"{CYAN}[*] Stopping search...{RESET}")
            break

        data = search_credentials(query, start, limit)
        if not data or not display_results(data, start):
            break

        start += limit


def interactive_mode():
    """Run the tool in interactive mode"""
    print_banner()

    # Check API status
    print(f"{CYAN}[*] Checking API status...{RESET}")
    is_online, status = check_api_status()

    if is_online:
        print(f"{GREEN}[✓] API Status: {status}{RESET}")
    else:
        print(f"{RED}[✗] API Status: {status}{RESET}")
        print(f"{RED}[!] Warning: API appears to be offline or unresponsive. Searches may fail.{RESET}")

    print(f"\n{YELLOW}Type 'help' for usage information or 'exit' to quit.{RESET}")
    print(f"{YELLOW}Just type an email or username to search.{RESET}\n")

    # Command loop
    while True:
        try:
            command = input(f"{GREEN}BreachPeek>{RESET} ").strip()

            if not command:
                continue

            # Parse command
            parts = command.split(maxsplit=1)
            cmd = parts[0].lower()

            if cmd in ['exit', 'quit', 'q']:
                print(f"{CYAN}[*] Exiting BreachPeek. Stay secure!{RESET}")
                break

            elif cmd == 'help':
                print_help()

            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()

            else:
                # Everything else is a search query
                if not is_online:
                    print(f"{RED}[ERROR] Cannot perform search: API is offline.{RESET}")
                    continue

                query = command.strip()
                perform_search(query)

        except KeyboardInterrupt:
            print(f"\n{CYAN}[*] Use 'exit' to quit.{RESET}")
        except EOFError:
            print(f"\n{CYAN}[*] Exiting BreachPeek. Stay secure!{RESET}")
            break


def main():
    """Main entry point"""
    # CLI mode
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description='BreachPeek - Hacked Database Search Tool (3.2B+ leaked credentials)',
            epilog='DISCLAIMER: For authorized security research only. Rate limited to ~100 requests/min.'
        )

        parser.add_argument('query', help='Email or username to search in database')
        parser.add_argument('-l', '--limit', type=int, default=DEFAULT_LIMIT,
                            help=f'Number of results per page (default: {DEFAULT_LIMIT}, max: {MAX_LIMIT})')

        args = parser.parse_args()

        if args.limit > MAX_LIMIT:
            print(f"{YELLOW}[WARNING] Limit exceeds API maximum. Using {MAX_LIMIT} instead.{RESET}")
            args.limit = MAX_LIMIT

        print_banner()

        is_online, status = check_api_status()
        print(f"{CYAN}[*] API Status: {status}{RESET}\n")

        if not is_online:
            print(f"{RED}[!] Warning: API appears to be offline or unresponsive. Search may fail.{RESET}\n")
        else:
            perform_search(args.query)

    else:
        # Interactive
        interactive_mode()


if __name__ == '__main__':

    main()
