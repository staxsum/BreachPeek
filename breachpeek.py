#!/usr/bin/env python3
"""
BreachPeek v2 - Offensive Security Intelligence
ProxyNova + HIBP integration for red team operations

GitHub: https://github.com/moscovium-mc/BreachPeek

DISCLAIMER: Authorized security research only. Unauthorized access is illegal.
Use at your own risk. Comply with CFAA 18 U.S.C. § 1030 and GDPR.
"""

from __future__ import annotations
import requests
import hashlib
import argparse
import sys
import time
import os
import signal
import random
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from urllib.parse import quote
from enum import Enum


# Configuration

class Config:
    """Global configuration constants"""
    PROXYNOVA_API: str = 'https://api.proxynova.com/comb'
    HIBP_BREACH_API: str = 'https://haveibeenpwned.com/api/v3'
    HIBP_PASSWORD_API: str = 'https://api.pwnedpasswords.com/range'
    
    DEFAULT_LIMIT: int = 100
    MAX_LIMIT: int = 100
    RATE_LIMIT_DELAY: float = 0.6
    PAGINATION_DELAY: float = 1.5
    REQUEST_TIMEOUT: int = 15
    API_CHECK_TIMEOUT: int = 5
    USER_AGENT: str = 'BreachPeek-CLI'
    
    # Retry configuration
    MAX_RETRIES: int = 3
    RETRY_BACKOFF_BASE: float = 2.0
    RETRY_JITTER_MAX: float = 1.0

# Terminal Colors

class Colors:
    """ANSI color codes for terminal output"""
    GREEN: str = '\033[92m'
    RED: str = '\033[91m'
    YELLOW: str = '\033[93m'
    CYAN: str = '\033[96m'
    BLUE: str = '\033[94m'
    MAGENTA: str = '\033[95m'
    WHITE: str = '\033[97m'
    DIM: str = '\033[2m'
    RESET: str = '\033[0m'
    BOLD: str = '\033[1m'


# Data Models

@dataclass
class PasswordCheckResult:
    """Result from HIBP password check"""
    is_pwned: bool
    count: int
    error: Optional[str] = None
    
    @property
    def is_safe(self) -> bool:
        """Check if password is safe to use"""
        return not self.is_pwned and self.error is None


@dataclass
class BreachRecord:
    """Single breach record from HIBP"""
    name: str
    title: str
    domain: str
    breach_date: str
    added_date: str
    modified_date: str
    pwn_count: int
    description: str
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    is_retired: bool
    is_spam_list: bool
    is_malware: bool
    is_stealer_log: bool
    is_subscription_free: bool
    logo_path: str
    attribution: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict) -> BreachRecord:
        """Create BreachRecord from API response"""
        return cls(
            name=data.get('Name', ''),
            title=data.get('Title', ''),
            domain=data.get('Domain', ''),
            breach_date=data.get('BreachDate', ''),
            added_date=data.get('AddedDate', ''),
            modified_date=data.get('ModifiedDate', ''),
            pwn_count=data.get('PwnCount', 0),
            description=data.get('Description', ''),
            data_classes=data.get('DataClasses', []),
            is_verified=data.get('IsVerified', False),
            is_fabricated=data.get('IsFabricated', False),
            is_sensitive=data.get('IsSensitive', False),
            is_retired=data.get('IsRetired', False),
            is_spam_list=data.get('IsSpamList', False),
            is_malware=data.get('IsMalware', False),
            is_stealer_log=data.get('IsStealerLog', False),
            is_subscription_free=data.get('IsSubscriptionFree', False),
            logo_path=data.get('LogoPath', ''),
            attribution=data.get('Attribution')
        )


@dataclass
class ProxyNovaResult:
    """Result from ProxyNova search"""
    count: int
    lines: List[Tuple[str, str]] = field(default_factory=list)
    error: Optional[str] = None
    retry_after: Optional[float] = None
    
    @classmethod
    def from_response(cls, data: Dict) -> ProxyNovaResult:
        """Parse ProxyNova API response"""
        if not data:
            return cls(count=0, error="No data received")
        
        count = data.get('count', 0)
        raw_lines = data.get('lines', [])
        
        # Parse email:password pairs
        lines = []
        for line in raw_lines:
            parts = line.split(':', 1)
            email = parts[0] if len(parts) > 0 else 'N/A'
            password = parts[1] if len(parts) > 1 else 'N/A'
            lines.append((email, password))
        
        return cls(count=count, lines=lines)


# Custom Exceptions

class BreachPeekError(Exception):
    """Base exception for BreachPeek"""
    pass


class APIError(BreachPeekError):
    """API request failed"""
    pass


class APITimeoutError(BreachPeekError):
    """API request timed out"""
    pass


class RateLimitError(BreachPeekError):
    """Rate limit exceeded"""
    pass


# API Clients

class HIBPClient:
    """Client for Have I Been Pwned API"""
    
    def __init__(self, config: Config = Config()):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.USER_AGENT})
    
    def check_password(self, password: str) -> PasswordCheckResult:
        """
        Check if password is compromised using k-anonymity
        Only sends first 5 chars of SHA-1 hash
        """
        try:
            # Generate SHA-1 hash
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query API
            url = f"{self.config.HIBP_PASSWORD_API}/{prefix}"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            # Search for our hash in results
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return PasswordCheckResult(is_pwned=True, count=int(count))
            
            return PasswordCheckResult(is_pwned=False, count=0)
            
        except requests.Timeout:
            return PasswordCheckResult(is_pwned=False, count=0, 
                                      error="Request timed out")
        except requests.RequestException as e:
            return PasswordCheckResult(is_pwned=False, count=0, 
                                      error=f"API error: {e}")
        except Exception as e:
            return PasswordCheckResult(is_pwned=False, count=0, 
                                      error=f"Error: {e}")
    
    def get_all_breaches(self) -> Tuple[Optional[List[BreachRecord]], Optional[str]]:
        """Fetch all breach records"""
        try:
            url = f"{self.config.HIBP_BREACH_API}/breaches"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            breaches = [BreachRecord.from_dict(b) for b in response.json()]
            return breaches, None
            
        except requests.Timeout:
            return None, "Request timed out"
        except requests.RequestException as e:
            return None, f"API error: {e}"
        except Exception as e:
            return None, f"Error: {e}"
    
    def get_breach_by_name(self, name: str) -> Tuple[Optional[BreachRecord], Optional[str]]:
        """Fetch specific breach details"""
        try:
            url = f"{self.config.HIBP_BREACH_API}/breach/{name}"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            breach = BreachRecord.from_dict(response.json())
            return breach, None
            
        except requests.Timeout:
            return None, "Request timed out"
        except requests.RequestException as e:
            return None, f"API error: {e}"
        except Exception as e:
            return None, f"Error: {e}"
    
    def get_latest_breach(self) -> Tuple[Optional[BreachRecord], Optional[str]]:
        """Fetch most recent breach"""
        try:
            url = f"{self.config.HIBP_BREACH_API}/latestbreach"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            breach = BreachRecord.from_dict(response.json())
            return breach, None
            
        except requests.Timeout:
            return None, "Request timed out"
        except requests.RequestException as e:
            return None, f"API error: {e}"
        except Exception as e:
            return None, f"Error: {e}"
    
    def search_breaches_by_domain(self, domain: str) -> Tuple[Optional[List[BreachRecord]], Optional[str]]:
        """Filter breaches by domain"""
        try:
            url = f"{self.config.HIBP_BREACH_API}/breaches?domain={domain}"
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            response.raise_for_status()
            
            breaches = [BreachRecord.from_dict(b) for b in response.json()]
            return breaches, None
            
        except requests.Timeout:
            return None, "Request timed out"
        except requests.RequestException as e:
            return None, f"API error: {e}"
        except Exception as e:
            return None, f"Error: {e}"
    
    def close(self) -> None:
        """Close HTTP session"""
        self.session.close()


class ProxyNovaClient:
    """Client for ProxyNova API with retry logic"""
    
    def __init__(self, config: Config = Config()):
        self.config = config
        self.session = requests.Session()
        self.last_request_time = 0.0
        self.request_count = 0
    
    def _rate_limit(self, is_pagination: bool = False) -> None:
        """Enforce rate limiting with jitter"""
        delay = self.config.PAGINATION_DELAY if is_pagination else self.config.RATE_LIMIT_DELAY
        
        # Add random jitter to avoid detection
        jitter = random.uniform(0, self.config.RETRY_JITTER_MAX)
        total_delay = delay + jitter
        
        elapsed = time.time() - self.last_request_time
        if elapsed < total_delay:
            time.sleep(total_delay - elapsed)
        
        self.last_request_time = time.time()
    
    def _make_request(self, url: str, attempt: int = 0) -> requests.Response:
        """Make HTTP request with retry logic"""
        try:
            response = self.session.get(url, timeout=self.config.REQUEST_TIMEOUT)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = float(response.headers.get('Retry-After', 60))
                raise RateLimitError(f"Rate limited. Retry after {retry_after}s")
            
            # Handle bad request with specific message
            if response.status_code == 400:
                if attempt < self.config.MAX_RETRIES:
                    # Exponential backoff for 400 errors
                    backoff = self.config.RETRY_BACKOFF_BASE ** attempt
                    jitter = random.uniform(0, self.config.RETRY_JITTER_MAX)
                    wait_time = backoff + jitter
                    
                    print(f"{Colors.YELLOW}[!] API returned 400, retrying in {wait_time:.1f}s... (attempt {attempt + 1}/{self.config.MAX_RETRIES}){Colors.RESET}")
                    time.sleep(wait_time)
                    return self._make_request(url, attempt + 1)
                else:
                    raise APIError(f"API returned 400 after {self.config.MAX_RETRIES} retries. The API may be blocking pagination.")
            
            response.raise_for_status()
            return response
            
        except requests.Timeout:
            if attempt < self.config.MAX_RETRIES:
                backoff = self.config.RETRY_BACKOFF_BASE ** attempt
                print(f"{Colors.YELLOW}[!] Timeout, retrying in {backoff:.1f}s...{Colors.RESET}")
                time.sleep(backoff)
                return self._make_request(url, attempt + 1)
            raise APITimeoutError(f"Request timed out after {self.config.MAX_RETRIES} retries")
        
        except RateLimitError:
            raise
        
        except requests.RequestException as e:
            if attempt < self.config.MAX_RETRIES:
                backoff = self.config.RETRY_BACKOFF_BASE ** attempt
                print(f"{Colors.YELLOW}[!] Request failed, retrying in {backoff:.1f}s...{Colors.RESET}")
                time.sleep(backoff)
                return self._make_request(url, attempt + 1)
            raise APIError(f"Request failed after {self.config.MAX_RETRIES} retries: {e}")
    
    def search(self, query: str, start: int = 0, 
               limit: int = None) -> ProxyNovaResult:
        """Search ProxyNova database with retry logic"""
        if limit is None:
            limit = self.config.DEFAULT_LIMIT
        
        limit = min(limit, self.config.MAX_LIMIT)
        
        try:
            # Rate limiting (extra delay for pagination)
            is_pagination = start > 0
            if is_pagination or self.request_count > 0:
                self._rate_limit(is_pagination)
            
            # Build request
            url = f"{self.config.PROXYNOVA_API}?query={quote(query)}&start={start}&limit={limit}"
            
            # Make request with retry logic
            response = self._make_request(url)
            self.request_count += 1
            
            return ProxyNovaResult.from_response(response.json())
            
        except RateLimitError as e:
            return ProxyNovaResult(count=0, error=str(e), retry_after=60.0)
        
        except APITimeoutError as e:
            return ProxyNovaResult(count=0, error=f"Timeout: {e}")
        
        except APIError as e:
            return ProxyNovaResult(count=0, error=str(e))
        
        except requests.RequestException as e:
            return ProxyNovaResult(count=0, error=f"Request error: {e}")
        
        except Exception as e:
            return ProxyNovaResult(count=0, error=f"Unexpected error: {e}")
    
    def close(self) -> None:
        """Close HTTP session"""
        self.session.close()


# Display/Formatting

class Display:
    """Terminal output formatter"""
    
    @staticmethod
    def banner() -> None:
        """ASCII banner"""
        banner = f"""{Colors.RED}
______     ______     ______     ______     ______     __  __     ______   ______     ______     __  __    
/\\  == \\   /\\  == \\   /\\  ___\\   /\\  __ \\   /\\  ___\\   /\\ \\_\\ \\   /\\  == \\ /\\  ___\\   /\\  ___\\   /\\ \\/ /    
\\ \\  __<   \\ \\  __<   \\ \\  __\\   \\ \\  __ \\  \\ \\ \\____  \\ \\  __ \\  \\ \\  _-/ \\ \\  __\\   \\ \\  __\\   \\ \\  _"-.  
 \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_____\\  \\ \\_\\ \\_\\  \\ \\_\\    \\ \\_____\\  \\ \\_____\\  \\ \\_\\ \\_\\ 
  \\/_____/   \\/_/ /_/   \\/_____/   \\/_/\\/_/   \\/_____/   \\/_/\\/_/   \\/_/     \\/_____/   \\/_____/   \\/_/\\/_/ 
                                                                                                            
{Colors.WHITE}Offensive Security Intelligence{Colors.RESET}
{Colors.CYAN}https://github.com/moscovium-mc/BreachPeek{Colors.RESET}
{Colors.DIM}ProxyNova (3.2B creds) + HIBP (570M+ hashes + breach intel){Colors.RESET}
"""
        print(banner)
    
    @staticmethod
    def intel_sources() -> None:
        """Display intelligence source statistics"""
        print(f"{Colors.CYAN}[*] Intelligence Sources{Colors.RESET}")
        print(f"    {Colors.WHITE}ProxyNova:{Colors.RESET} {Colors.GREEN}3.2B+{Colors.RESET} credentials across multiple breaches")
        print(f"    {Colors.WHITE}HIBP Passwords:{Colors.RESET} {Colors.GREEN}570M+{Colors.RESET} compromised password hashes")
        print(f"    {Colors.WHITE}HIBP Breaches:{Colors.RESET} {Colors.GREEN}928+{Colors.RESET} breach records with full metadata")
    
    @staticmethod
    def breach_info(breach: BreachRecord) -> None:
        """Format breach record"""
        import re
        
        print(f"\n{Colors.BOLD}{Colors.RED}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}{breach.title}{Colors.RESET}")
        print(f"{Colors.RED}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}Domain:{Colors.RESET} {breach.domain}")
        print(f"{Colors.CYAN}Breach Date:{Colors.RESET} {breach.breach_date}")
        print(f"{Colors.CYAN}Added to HIBP:{Colors.RESET} {breach.added_date}")
        print(f"{Colors.CYAN}Pwn Count:{Colors.RESET} {breach.pwn_count:,} accounts")
        print(f"{Colors.CYAN}Data Classes:{Colors.RESET} {', '.join(breach.data_classes)}")
        
        # Status flags
        flags = []
        if breach.is_verified:
            flags.append(f"{Colors.GREEN}[VERIFIED]{Colors.RESET}")
        if breach.is_sensitive:
            flags.append(f"{Colors.RED}[SENSITIVE]{Colors.RESET}")
        if breach.is_spam_list:
            flags.append(f"{Colors.YELLOW}[SPAM]{Colors.RESET}")
        if breach.is_malware:
            flags.append(f"{Colors.MAGENTA}[MALWARE]{Colors.RESET}")
        
        if flags:
            print(f"{Colors.CYAN}Flags:{Colors.RESET} {' '.join(flags)}")
        
        # Strip HTML
        description = re.sub('<[^<]+?>', '', breach.description)
        print(f"\n{Colors.DIM}{description}{Colors.RESET}")
        print(f"{Colors.RED}{'='*80}{Colors.RESET}\n")
    
    @staticmethod
    def proxynova_results(result: ProxyNovaResult, start_index: int = 0) -> bool:
        """Format ProxyNova results"""
        if result.error:
            print(f"{Colors.RED}[!] {result.error}{Colors.RESET}")
            if result.retry_after:
                print(f"{Colors.YELLOW}[!] Wait {result.retry_after:.0f}s before retrying{Colors.RESET}")
            return False
        
        if not result.lines:
            print(f"{Colors.YELLOW}[!] No results found{Colors.RESET}")
            return False
        
        print(f"\n{Colors.BOLD}{'#':<8} {'EMAIL/USERNAME':<45} {'PASSWORD':<25}{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 80}{Colors.RESET}")
        
        for i, (email, password) in enumerate(result.lines, start=start_index + 1):
            print(f"{Colors.CYAN}{i:<8}{Colors.RESET} {email:<45} {Colors.RED}{password:<25}{Colors.RESET}")
        
        return True
    
    @staticmethod
    def breach_list(breaches: List[BreachRecord], limit: int = 50) -> None:
        """Format breach list"""
        # Sort by impact
        sorted_breaches = sorted(breaches, key=lambda x: x.pwn_count, reverse=True)
        
        print(f"{Colors.BOLD}{'BREACH':<30} {'DOMAIN':<25} {'PWN COUNT':>15} {'DATE':<12}{Colors.RESET}")
        print(f"{Colors.DIM}{'-' * 85}{Colors.RESET}")
        
        for breach in sorted_breaches[:limit]:
            title = breach.title[:28]
            domain = breach.domain[:23]
            
            print(f"{Colors.WHITE}{title:<30}{Colors.RESET} "
                  f"{Colors.CYAN}{domain:<25}{Colors.RESET} "
                  f"{Colors.RED}{breach.pwn_count:>15,}{Colors.RESET} "
                  f"{Colors.DIM}{breach.breach_date:<12}{Colors.RESET}")
        
        if len(breaches) > limit:
            print(f"\n{Colors.DIM}[i] Showing top {limit} of {len(breaches)} total{Colors.RESET}")
    
    @staticmethod
    def help_text() -> None:
        """Command reference"""
        help_text = f"""
{Colors.BOLD}{Colors.WHITE}COMMAND REFERENCE{Colors.RESET}

{Colors.BOLD}{Colors.RED}[ProxyNova - Credential Search]{Colors.RESET}
  {Colors.GREEN}search <query>{Colors.RESET}          Search email:password database
  {Colors.GREEN}<email/username>{Colors.RESET}        Quick search (no command needed)

{Colors.BOLD}{Colors.RED}[HIBP - Password Intelligence]{Colors.RESET}
  {Colors.GREEN}checkpw <password>{Colors.RESET}      Check if password is compromised
  {Colors.GREEN}pw <password>{Colors.RESET}           Quick password check

{Colors.BOLD}{Colors.RED}[HIBP - Breach Intelligence]{Colors.RESET}
  {Colors.GREEN}breaches{Colors.RESET}                List all breaches
  {Colors.GREEN}breaches <domain>{Colors.RESET}       Filter by domain
  {Colors.GREEN}breach <name>{Colors.RESET}           Get breach details
  {Colors.GREEN}latest{Colors.RESET}                  Show newest breach

{Colors.BOLD}{Colors.RED}[System]{Colors.RESET}
  {Colors.GREEN}help{Colors.RESET}                    Show this menu
  {Colors.GREEN}clear{Colors.RESET}                   Clear screen
  {Colors.GREEN}exit{Colors.RESET} / {Colors.GREEN}quit{Colors.RESET}             Exit BreachPeek

{Colors.BOLD}{Colors.WHITE}EXAMPLES{Colors.RESET}
  {Colors.CYAN}search john@example.com{Colors.RESET}
  {Colors.CYAN}checkpw Password123{Colors.RESET}
  {Colors.CYAN}breach Adobe{Colors.RESET}
  {Colors.CYAN}breaches linkedin.com{Colors.RESET}
  {Colors.CYAN}latest{Colors.RESET}

{Colors.BOLD}{Colors.WHITE}OPSEC NOTES{Colors.RESET}
  {Colors.DIM}• Always use unique passwords per service
  • Enable 2FA/MFA wherever possible
  • Rotate credentials found in breaches immediately
  • Monitor for new breach additions regularly{Colors.RESET}
"""
        print(help_text)


# CLI Interface

class BreachPeekCLI:
    """Interactive command-line interface"""
    
    def __init__(self, config: Config = Config()):
        self.config = config
        self.hibp = HIBPClient(config)
        self.proxynova = ProxyNovaClient(config)
        self.display = Display()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle interrupt signals"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Interrupted. Cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        self.hibp.close()
        self.proxynova.close()
    
    def cmd_search(self, query: str) -> None:
        """Search ProxyNova database"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Searching ProxyNova for: {Colors.WHITE}{query}{Colors.RESET}")
        
        start = 0
        result = self.proxynova.search(query, start)
        
        if result.error:
            print(f"{Colors.RED}[!] {result.error}{Colors.RESET}")
            return
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Found {Colors.WHITE}{result.count}{Colors.RESET} results")
        
        if not self.display.proxynova_results(result, start):
            return
        
        start += self.config.DEFAULT_LIMIT
        
        # Pagination
        while start < result.count and self.running:
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Showing {start}/{result.count}")
            print(f"{Colors.DIM}[i] ProxyNova may rate-limit pagination. Delays are automatic.{Colors.RESET}")
            
            try:
                user_input = input(f"{Colors.YELLOW}[?]{Colors.RESET} Load more? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            
            if user_input != 'y':
                break
            
            result = self.proxynova.search(query, start)
            
            # Check for errors (including rate limiting)
            if result.error:
                print(f"{Colors.RED}[!] {result.error}{Colors.RESET}")
                
                # If it's a persistent error, offer to stop
                if "400 after" in result.error or "Rate limited" in result.error:
                    try:
                        continue_input = input(f"{Colors.YELLOW}[?]{Colors.RESET} Continue trying? (y/n): ").strip().lower()
                        if continue_input != 'y':
                            break
                    except (EOFError, KeyboardInterrupt):
                        break
                else:
                    break
            
            if not self.display.proxynova_results(result, start):
                break
            
            start += self.config.DEFAULT_LIMIT
    
    def cmd_check_password(self, password: str) -> None:
        """Check password compromise status"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Querying HIBP...")
        
        result = self.hibp.check_password(password)
        
        if result.error:
            print(f"{Colors.RED}[!] {result.error}{Colors.RESET}")
            return
        
        if result.is_pwned:
            print(f"{Colors.RED}{Colors.BOLD}[!!!] COMPROMISED [!!!]{Colors.RESET}")
            print(f"{Colors.RED}[!]{Colors.RESET} Seen {Colors.WHITE}{result.count:,}{Colors.RESET} times in breaches")
            print(f"{Colors.YELLOW}[!]{Colors.RESET} Change this password immediately on all accounts")
        else:
            print(f"{Colors.GREEN}[✓]{Colors.RESET} Not found in HIBP database")
            print(f"{Colors.DIM}    Note: Absence doesn't guarantee strength{Colors.RESET}")
    
    def cmd_list_breaches(self, domain: Optional[str] = None) -> None:
        """List breach records"""
        if domain:
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Fetching breaches for: {Colors.WHITE}{domain}{Colors.RESET}")
            breaches, error = self.hibp.search_breaches_by_domain(domain)
        else:
            print(f"\n{Colors.CYAN}[*]{Colors.RESET} Fetching all HIBP breaches...")
            breaches, error = self.hibp.get_all_breaches()
        
        if error:
            print(f"{Colors.RED}[!] {error}{Colors.RESET}")
            return
        
        if not breaches:
            print(f"{Colors.YELLOW}[!] No breaches found{Colors.RESET}")
            return
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Found {Colors.WHITE}{len(breaches)}{Colors.RESET} breaches\n")
        self.display.breach_list(breaches)
    
    def cmd_breach_info(self, name: str) -> None:
        """Get detailed breach intel"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Fetching: {Colors.WHITE}{name}{Colors.RESET}")
        
        breach, error = self.hibp.get_breach_by_name(name)
        
        if error:
            print(f"{Colors.RED}[!] {error}{Colors.RESET}")
            return
        
        self.display.breach_info(breach)
    
    def cmd_latest_breach(self) -> None:
        """Show newest breach"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Fetching latest breach...")
        
        breach, error = self.hibp.get_latest_breach()
        
        if error:
            print(f"{Colors.RED}[!] {error}{Colors.RESET}")
            return
        
        print(f"{Colors.GREEN}[+]{Colors.RESET} Latest addition to HIBP:")
        self.display.breach_info(breach)
    
    def run_interactive(self) -> None:
        """Run interactive shell"""
        self.display.banner()
        self.display.intel_sources()
        
        print(f"\n{Colors.DIM}Type 'help' for commands{Colors.RESET}\n")
        
        # Main loop
        while self.running:
            try:
                command = input(f"{Colors.RED}breach{Colors.RESET}{Colors.WHITE}@{Colors.RESET}"
                              f"{Colors.CYAN}peek{Colors.RESET} {Colors.RED}»{Colors.RESET} ").strip()
                
                if not command:
                    continue
                
                self._process_command(command)
                
            except KeyboardInterrupt:
                print(f"\n{Colors.DIM}Use 'exit' to quit{Colors.RESET}")
                continue
            except EOFError:
                print(f"\n{Colors.CYAN}[*]{Colors.RESET} Exiting. Stay safe.")
                break
            except Exception as e:
                print(f"{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
    
    def _process_command(self, command: str) -> None:
        """Route command to handler"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None
        
        # Command routing
        if cmd in ['exit', 'quit', 'q']:
            print(f"{Colors.CYAN}[*]{Colors.RESET} Exiting. Stay safe.")
            self.running = False
        
        elif cmd == 'help':
            self.display.help_text()
        
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.display.banner()
        
        elif cmd == 'search':
            if arg:
                self.cmd_search(arg)
            else:
                print(f"{Colors.RED}[!]{Colors.RESET} Usage: search <email/username>")
        
        elif cmd in ['checkpw', 'pw']:
            if arg:
                self.cmd_check_password(arg)
            else:
                print(f"{Colors.RED}[!]{Colors.RESET} Usage: checkpw <password>")
        
        elif cmd == 'breaches':
            self.cmd_list_breaches(arg)
        
        elif cmd == 'breach':
            if arg:
                self.cmd_breach_info(arg)
            else:
                print(f"{Colors.RED}[!]{Colors.RESET} Usage: breach <name>")
        
        elif cmd == 'latest':
            self.cmd_latest_breach()
        
        else:
            # Default: ProxyNova search
            self.cmd_search(command)
    
    def run_cli(self, args: argparse.Namespace) -> None:
        """Run single CLI command"""
        self.display.banner()
        
        if args.command == 'search':
            self.cmd_search(args.query)
        elif args.command == 'checkpw':
            self.cmd_check_password(args.password)
        elif args.command == 'breaches':
            self.cmd_list_breaches(args.domain)
        elif args.command == 'breach':
            self.cmd_breach_info(args.name)
        elif args.command == 'latest':
            self.cmd_latest_breach()


# Main Entry Point

def main() -> None:
    """Application entry point"""
    config = Config()
    
    if len(sys.argv) > 1:
        # CLI mode with argparse
        parser = argparse.ArgumentParser(
            description='BreachPeek v2 - Offensive Security Intelligence',
            epilog='ProxyNova + HIBP integration for red team ops'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Define subcommands
        search_parser = subparsers.add_parser('search', help='Search ProxyNova')
        search_parser.add_argument('query', help='Email or username')
        
        pw_parser = subparsers.add_parser('checkpw', help='Check password')
        pw_parser.add_argument('password', help='Password to check')
        
        breaches_parser = subparsers.add_parser('breaches', help='List breaches')
        breaches_parser.add_argument('domain', nargs='?', help='Filter by domain')
        
        breach_parser = subparsers.add_parser('breach', help='Breach details')
        breach_parser.add_argument('name', help='Breach name')
        
        subparsers.add_parser('latest', help='Latest breach')
        
        args = parser.parse_args()
        
        if args.command:
            cli = BreachPeekCLI(config)
            try:
                cli.run_cli(args)
            finally:
                cli.cleanup()
        else:
            parser.print_help()
    
    else:
        # Interactive mode
        cli = BreachPeekCLI(config)
        try:
            cli.run_interactive()
        finally:
            cli.cleanup()


if __name__ == '__main__':
    main()
