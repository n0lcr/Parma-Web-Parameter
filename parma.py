import re
import sys
import json
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from collections import defaultdict
from datetime import datetime
import time
from typing import Set, Dict, List, Tuple
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import threading
import concurrent.futures
import psutil
import os
import xml.etree.ElementTree as ET

# Initialize colorama for colored terminal output
init(autoreset=True)

def get_memory_usage():
    """Get current memory usage in MB"""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024

class WebScanner:
    def __init__(self, target_url: str, max_depth: int = 3, delay: float = 0.5,
                 timeout: int = 10, user_agent: str = None, max_threads: int = 20,
                 output_file: str = None, custom_filter: str = None, time_sec_mode: bool = False,
                 use_tor: bool = False, https_only: bool = False, 
                 disable_coloring: bool = False, save_param_file: str = None, 
                 save_endpoints_file: str = None):
        """
        Initialize the web scanner
        """
        self.target_url = target_url.rstrip('/')
        parsed_url = urlparse(target_url)
        self.domain = parsed_url.netloc
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        self.max_threads = max_threads
        self.output_file = output_file
        self.custom_filter = custom_filter
        self.time_sec_mode = time_sec_mode
        self.use_tor = use_tor
        self.https_only = https_only
        self.disable_coloring = disable_coloring
        self.save_param_file = save_param_file
        self.save_endpoints_file = save_endpoints_file

        # Set colors based on disable_coloring flag
        if self.disable_coloring:
            self.CYAN = self.RED = self.GREEN = self.YELLOW = self.LIGHTBLACK_EX = ""
            self.RESET_ALL = ""
        else:
            self.CYAN = Fore.CYAN
            self.RED = Fore.RED
            self.GREEN = Fore.GREEN
            self.YELLOW = Fore.YELLOW
            self.LIGHTBLACK_EX = Fore.LIGHTBLACK_EX
            self.RESET_ALL = Style.RESET_ALL

        # Domain parsing
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            self.base_domain = '.'.join(domain_parts[-2:])
        else:
            self.base_domain = self.domain

        # Optimized data structures
        self.visited_urls: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = [(self.target_url, 0)]
        self.lock = threading.Lock()

        # Statistics
        self.start_time = None
        self.errors = 0
        self.requests_count = 0
        self.last_pause_count = 0

        # Parameters storage
        self.parameters_found: Set[str] = set()
        
        # Endpoints storage
        self.endpoints_found: Set[str] = set()

        # Optimized results storage
        self.results = {
            'links': {'internal': [], 'external': []},
            'api_endpoints': [],
            'js_files': [],
            'forms': [],
            'hidden_fields': [],
            'comments': [],
            'cookies': [],
            'local_storage': [],
            'webpack_chunks': [],
            'source_maps': [],
            'subdomains': [],
            'potential_vulnerabilities': [],
            'xml_files': [],
            'parameters': [],
            'endpoints': []
        }

        # Session with custom headers
        self.session = requests.Session()

        # TOR proxy configuration
        if self.use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

        self.session.headers.update({
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        # Compiled regex patterns for better performance
        self.patterns = {
            'api_endpoint': re.compile(r'(?:api|endpoint|route)["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            'url_pattern': re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+'),
            'relative_url': re.compile(r'["\'](/[a-zA-Z0-9_\-/.?&=]+)["\']'),
            'subdomain': re.compile(r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.base_domain) + r')'),
            'fetch_call': re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
            'axios_call': re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']'),
            'ajax_call': re.compile(r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']'),
            'websocket': re.compile(r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']'),
            'graphql': re.compile(r'(?:graphql|gql)`([^`]+)`'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_+/=]*'),
            'api_key': re.compile(r'(?:api[_\-]?key|apikey|access[_\-]?token)["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'webpack_chunk': re.compile(r'["\']([^"\']*chunk[^"\']*\.js)["\']', re.IGNORECASE),
            'sourcemap': re.compile(r'sourceMappingURL=([^\s]+)'),
            'parameter': re.compile(r'[\?&]([a-zA-Z0-9_\-]+)=[^&\s]+'),
            'endpoint_extract': re.compile(r'https?://[^/]+(/.*)'),
        }

        # Create output files if specified
        if self.output_file:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Web Scanner Results - {self.target_url}\n")
                f.write(f"# Started at: {datetime.now().isoformat()}\n")
                f.write("# Format: FULL_URL\n")
                f.write("# =====================\n\n")

        if self.save_param_file:
            with open(self.save_param_file, 'w', encoding='utf-8') as f:
                f.write(f"# URL Parameters Found - {self.target_url}\n")
                f.write(f"# Started at: {datetime.now().isoformat()}\n")
                f.write("# Format: PARAMETER_NAME\n")
                f.write("# =====================\n\n")

        if self.save_endpoints_file:
            with open(self.save_endpoints_file, 'w', encoding='utf-8') as f:
                f.write(f"# URL Endpoints Found - {self.target_url}\n")
                f.write(f"# Started at: {datetime.now().isoformat()}\n")
                f.write("# Format: ENDPOINT_PATH\n")
                f.write("# =====================\n\n")

    def extract_endpoint_from_url(self, full_url: str) -> str:
        """
        Extract endpoint from full URL
        """
        try:
            # Regex ile endpoint extraction
            match = self.patterns['endpoint_extract'].match(full_url)
            if match:
                endpoint = match.group(1)
                return endpoint if endpoint else "/"
            
            # Alternatif yöntem: Manuel extraction
            url_without_protocol = full_url.replace("https://", "").replace("http://", "")
            first_slash_index = url_without_protocol.find('/')
            
            if first_slash_index != -1:
                endpoint = url_without_protocol[first_slash_index:]
                return endpoint
            else:
                return "/"
                
        except Exception as e:
            return "/"

    def save_endpoint_to_file(self, endpoint: str):
        """Save endpoint to endpoints file"""
        if self.save_endpoints_file and endpoint:
            try:
                with self.lock:
                    with open(self.save_endpoints_file, 'a', encoding='utf-8') as f:
                        f.write(f"{endpoint}\n")
            except Exception as e:
                print(f"{self.RED}[-] Error saving endpoint to file: {str(e)}{self.RESET_ALL}")

    def save_all_endpoints_to_file(self):
        """Tüm endpoint'leri endpoints dosyasına kaydet"""
        if self.save_endpoints_file and self.results['endpoints']:
            try:
                with self.lock:
                    with open(self.save_endpoints_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n# Total unique endpoints found: {len(set(self.results['endpoints']))}\n")
                        f.write(f"# Scan completed at: {datetime.now().isoformat()}\n")
            except Exception as e:
                print(f"{self.RED}[-] Error saving final endpoint count: {str(e)}{self.RESET_ALL}")

    def add_unique_endpoint(self, endpoint: str):
        """Endpoint'i ekle (benzersiz olarak)"""
        if endpoint and endpoint not in self.endpoints_found:
            self.endpoints_found.add(endpoint)
            self.results['endpoints'].append(endpoint)
            if self.save_endpoints_file:
                self.save_endpoint_to_file(endpoint)

    def process_url_for_endpoints(self, url: str):
        """URL'yi endpoint extraction için işle"""
        if self.is_valid_url(url) and self.is_same_domain(url):
            endpoint = self.extract_endpoint_from_url(url)
            self.add_unique_endpoint(endpoint)

    def print_banner(self):
        """Print tool banner"""
        # Yeni banner
        banner = f"""
{self.LIGHTBLACK_EX}                                   
___________ _______  _____ _____   
\\____ \\__  \\\\_  __ \\/     \\\\__  \\  
|  |_> > __ \\|  | \\/  Y Y  \\/ __ \\_
|   __(____  /__|  |__|_|  (____  /
|__|       \\/            \\/     \\/  
{self.RESET_ALL}
"""
        print(banner)

        info = f"""
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Method           : DEEP SCAN{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} URL              : {self.target_url}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Max Depth        : {self.max_depth}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Threads          : {self.max_threads}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Delay            : {self.delay}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Custom Filter    : {self.custom_filter if self.custom_filter else 'None'}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Time Sec Mode    : {self.time_sec_mode}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} TOR Proxy        : {self.use_tor}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} HTTPS Only       : {self.https_only}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Param File       : {self.save_param_file if self.save_param_file else 'None'}{self.RESET_ALL}
{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Endpoints File   : {self.save_endpoints_file if self.save_endpoints_file else 'None'}{self.RESET_ALL}
"""
        print(info)

    def add_unique_item(self, category: str, subcategory: str, item: str):
        """Optimized method to add unique items to results"""
        if subcategory:
            if item not in self.results[category][subcategory]:
                self.results[category][subcategory].append(item)
        else:
            if item not in self.results[category]:
                self.results[category].append(item)

    def extract_parameters_from_url(self, url: str):
        """Extract parameters from URL and save them"""
        try:
            parsed = urlparse(url)

            # Query parametrelerini çıkar
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params.keys():
                    if param and param not in self.parameters_found:
                        self.parameters_found.add(param)
                        self.results['parameters'].append(param)

                        if self.save_param_file:
                            self.save_parameter_to_file(param)

        except Exception as e:
            pass

    def save_parameter_to_file(self, param: str):
        """Save parameter to parameter file"""
        try:
            with self.lock:
                with open(self.save_param_file, 'a', encoding='utf-8') as f:
                    f.write(f"{param}\n")
        except Exception as e:
            print(f"{self.RED}[-] Error saving parameter to file: {str(e)}{self.RESET_ALL}")

    def save_all_parameters_to_file(self):
        """Tüm parametreleri parametre dosyasına kaydet"""
        if self.save_param_file and self.results['parameters']:
            try:
                with self.lock:
                    with open(self.save_param_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n# Total unique parameters found: {len(set(self.results['parameters']))}\n")
                        f.write(f"# Scan completed at: {datetime.now().isoformat()}\n")
            except Exception as e:
                print(f"{self.RED}[-] Error saving final parameter count: {str(e)}{self.RESET_ALL}")

    def matches_custom_filter(self, url: str) -> bool:
        """Check if URL matches custom filter"""
        if not self.custom_filter:
            return True
        return self.custom_filter.lower() in url.lower()

    def save_to_output_file(self, url: str):
        """Save URL to output file if specified"""
        if self.output_file and self.matches_custom_filter(url):
            try:
                with self.lock:
                    with open(self.output_file, 'a', encoding='utf-8') as f:
                        f.write(f"{url}\n")
            except Exception as e:
                print(f"{self.RED}[-] Error saving to output file: {str(e)}{self.RESET_ALL}")

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            result = urlparse(url)
            if self.https_only and result.scheme != 'https':
                return False
            return all([result.scheme, result.netloc])
        except:
            return False

    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain"""
        return urlparse(url).netloc.endswith(self.base_domain)

    def should_process_url(self, url: str) -> bool:
        """Check if URL should be processed based on custom filter"""
        if not self.custom_filter:
            return True
        return self.matches_custom_filter(url)

    def fetch_url(self, url: str) -> tuple:
        """
        Fetch URL content
        """
        try:
            with self.lock:
                self.requests_count += 1

            # Extract parameters from URL before fetching
            self.extract_parameters_from_url(url)
            
            # Extract endpoints from URL
            self.process_url_for_endpoints(url)

            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Check if content is HTML before processing
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and not url.endswith(('.js', '.xml')):
                return None, content_type, response.status_code
                
            return response.text, content_type, response.status_code
        except Exception as e:
            with self.lock:
                self.errors += 1
            return None, None, None

    def analyze_xml_content(self, content: str, url: str):
        """Analyze XML content for links and endpoints"""
        try:
            for match in self.patterns['url_pattern'].finditer(content):
                found_url = match.group(0)
                if self.is_valid_url(found_url) and self.should_process_url(found_url):
                    if self.is_same_domain(found_url):
                        self.add_unique_item('links', 'internal', found_url)
                        self.save_to_output_file(found_url)
                        self.process_url_for_endpoints(found_url)
                        if found_url not in self.visited_urls and found_url not in [u for u, d in self.to_visit]:
                            self.to_visit.append((found_url, 0))
                    else:
                        self.add_unique_item('links', 'external', found_url)
                        self.save_to_output_file(found_url)

            self.add_unique_item('xml_files', '', url)

        except Exception as e:
            pass

    def extract_links(self, soup: BeautifulSoup, base_url: str, current_depth: int):
        """Extract all links from HTML"""
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'frame', 'embed', 'source']):
            url = None

            if tag.name == 'a':
                url = tag.get('href')
            elif tag.name in ['link', 'script', 'img', 'iframe', 'frame', 'embed', 'source']:
                url = tag.get('src') or tag.get('href')

            if url:
                if url.startswith('//'):
                    url = 'https:' + url
                elif url.startswith('/'):
                    url = urljoin(base_url, url)
                elif not url.startswith(('http://', 'https://', 'mailto:', 'tel:', 'javascript:', '#')):
                    url = urljoin(base_url, '/' + url.lstrip('/'))

                url = url.split('#')[0]

                if self.is_valid_url(url) and self.should_process_url(url):
                    self.extract_parameters_from_url(url)
                    self.process_url_for_endpoints(url)

                    if self.is_same_domain(url):
                        self.add_unique_item('links', 'internal', url)
                        self.save_to_output_file(url)
                        if url not in self.visited_urls and url not in [u for u, d in self.to_visit]:
                            self.to_visit.append((url, current_depth + 1))
                    else:
                        self.add_unique_item('links', 'external', url)
                        self.save_to_output_file(url)

    def extract_forms(self, soup: BeautifulSoup, base_url: str):
        """Extract forms and hidden fields"""
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url

            form_data = {
                'url': action_url,
                'method': method,
                'fields': []
            }

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                field = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                }

                if field['type'] == 'hidden':
                    self.results['hidden_fields'].append({
                        'url': base_url,
                        'name': field['name'],
                        'value': field['value']
                    })

                form_data['fields'].append(field)

            self.results['forms'].append(form_data)

    def extract_comments(self, soup: BeautifulSoup, base_url: str):
        """Extract HTML and JavaScript comments"""
        from bs4 import Comment

        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = comment.strip()
            if len(comment_text) > 10:
                self.results['comments'].append({
                    'url': base_url,
                    'content': comment_text
                })

    def analyze_javascript(self, content: str, url: str):
        """Deep analysis of JavaScript code"""

        # JavaScript analizi basitleştirildi
        for match in self.patterns['url_pattern'].finditer(content):
            found_url = match.group(0)
            if self.is_valid_url(found_url) and self.should_process_url(found_url):
                if self.is_same_domain(found_url):
                    self.add_unique_item('api_endpoints', '', found_url)
                    self.save_to_output_file(found_url)
                    self.process_url_for_endpoints(found_url)

        for match in self.patterns['relative_url'].finditer(content):
            path = match.group(1)
            if path.startswith('/'):
                full_url = urljoin(self.target_url, path)
                if self.is_valid_url(full_url) and self.should_process_url(full_url):
                    self.add_unique_item('api_endpoints', '', full_url)
                    self.save_to_output_file(full_url)
                    self.process_url_for_endpoints(full_url)

    def scan_url(self, url: str, depth: int):
        """Scan a single URL"""
        if url in self.visited_urls or depth > self.max_depth or not self.should_process_url(url):
            return

        with self.lock:
            self.visited_urls.add(url)

        content, content_type, status_code = self.fetch_url(url)

        if not content or status_code != 200:
            return

        if 'xml' in content_type or url.endswith(('.xml', '.rss', '.atom')):
            self.analyze_xml_content(content, url)
            return

        if 'javascript' in content_type or url.endswith('.js'):
            with self.lock:
                self.add_unique_item('js_files', '', url)
            self.analyze_javascript(content, url)
            return

        if 'html' in content_type:
            try:
                soup = BeautifulSoup(content, 'html.parser')

                self.extract_links(soup, url, depth)
                self.extract_forms(soup, url)
                self.extract_comments(soup, url)

                for script in soup.find_all('script'):
                    if script.string:
                        self.analyze_javascript(script.string, url)

                for script in soup.find_all('script', src=True):
                    js_url = urljoin(url, script['src'])
                    if self.is_valid_url(js_url) and self.should_process_url(js_url):
                        with self.lock:
                            self.add_unique_item('js_files', '', js_url)
                        if js_url not in self.visited_urls and self.is_same_domain(js_url):
                            self.to_visit.append((js_url, depth + 1))

            except Exception as e:
                with self.lock:
                    self.errors += 1

        time.sleep(self.delay)

    def print_progress(self):
        """Print progress information - SADE VE SABİT"""
        scanned = len(self.visited_urls)
        endpoints_found = len(set(self.results['endpoints']))
        
        progress_text = f"{self.RED}:: URL : [{scanned}] :: Endpoint : [{endpoints_found}] ::{self.RESET_ALL}"
        
        # Her zaman aynı satırda göster
        print(f"\r{progress_text}", end='', flush=True)

    def check_time_sec_mode(self):
        """Check if we need to pause due to time security mode"""
        if self.time_sec_mode:
            scanned_count = len(self.visited_urls)
            if scanned_count - self.last_pause_count >= 1000:
                print(f"\n{self.YELLOW}[!] Time Security Mode: 1000 links scanned, pausing for 45 seconds...{self.RESET_ALL}")
                time.sleep(45)
                self.last_pause_count = scanned_count
                print(f"{self.GREEN}[+] Resuming scan...{self.RESET_ALL}")

    def scan(self):
        """Main scanning function"""
        self.print_banner()

        self.start_time = time.time()

        print(f"{self.GREEN}[+] Starting scan...{self.RESET_ALL}")
        
        # İlk progress gösterimi
        self.print_progress()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []

            while self.to_visit or futures:
                self.check_time_sec_mode()

                while self.to_visit and len(futures) < self.max_threads:
                    url, depth = self.to_visit.pop(0)
                    future = executor.submit(self.scan_url, url, depth)
                    futures.append(future)

                done, not_done = concurrent.futures.wait(futures, timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)

                for future in done:
                    try:
                        future.result()
                    except Exception as e:
                        with self.lock:
                            self.errors += 1
                    futures.remove(future)

                # Progress'i güncelle - aynı satırda
                self.print_progress()

        # Son satırı temizle ve yeni satıra geç
        print("\n")

        if self.output_file:
            print(f"{self.GREEN}[✓] URLs saved to: {self.output_file}{self.RESET_ALL}")

        if self.save_param_file:
            self.save_all_parameters_to_file()
            print(f"{self.GREEN}[✓] Parameters saved to: {self.save_param_file}{self.RESET_ALL}")

        if self.save_endpoints_file:
            self.save_all_endpoints_to_file()
            print(f"{self.GREEN}[✓] Endpoints saved to: {self.save_endpoints_file}{self.RESET_ALL}")

        print(f"{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Scan completed in {time.time() - self.start_time:.2f} seconds{self.RESET_ALL}")

        print(f"{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Total URLs found: {len(self.visited_urls)}{self.RESET_ALL}")
        print(f"{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Total parameters found: {len(set(self.results['parameters']))}{self.RESET_ALL}")
        print(f"{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Total endpoints found: {len(set(self.results['endpoints']))}{self.RESET_ALL}")
        print()

    def print_results(self):
        """Print scan results to terminal"""
        if self.results['parameters']:
            print(f"\n{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Parameters Found {self.RED}::{self.RESET_ALL}")
            for param in sorted(set(self.results['parameters'])):
                print(f"{self.LIGHTBLACK_EX}    {param}{self.RESET_ALL}")

        if self.results['endpoints']:
            print(f"\n{self.RED}::{self.RESET_ALL}{self.LIGHTBLACK_EX} Endpoints Found {self.RED}::{self.RESET_ALL}")
            # Sadece ilk 20 endpoint'i göster
            for endpoint in sorted(set(self.results['endpoints']))[:20]:
                print(f"{self.LIGHTBLACK_EX}    {endpoint}{self.RESET_ALL}")
            if len(self.results['endpoints']) > 20:
                print(f"{self.LIGHTBLACK_EX}    ... and {len(self.results['endpoints']) - 20} more{self.RESET_ALL}")

        print()

def main():
    parser = argparse.ArgumentParser(
        description='PARMA - Advanced Web Scanner for Parameter and Endpoint Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python parma.py -u https://example.com
  python parma.py -u https://example.com --savemeter endpoints.txt
  python parma.py -u https://example.com --output urls.txt
        """
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--threads', type=int, default=20, help='Maximum concurrent threads (default: 20)')
    parser.add_argument('--output', help='Output text file path for URLs')
    parser.add_argument('--savemeter', help='Output file for URL endpoints (extracts paths after domain)')
    parser.add_argument('--custom', help='Custom domain filter')
    parser.add_argument('--time-sec-mode', action='store_true', help='Enable time security mode')
    parser.add_argument('--tor', action='store_true', help='Use TOR proxy for requests')
    parser.add_argument('--https-only', action='store_true', help='Only scan HTTPS URLs')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--disable-coloring', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    try:
        scanner = WebScanner(
            target_url=args.url,
            max_depth=3,
            delay=args.delay,
            timeout=10,
            user_agent=args.user_agent,
            max_threads=args.threads,
            output_file=args.output,
            custom_filter=args.custom,
            time_sec_mode=args.time_sec_mode,
            use_tor=args.tor,
            https_only=args.https_only,
            disable_coloring=args.disable_coloring,
            save_param_file=None,
            save_endpoints_file=args.savemeter
        )

        scanner.scan()
        scanner.print_results()

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        try:
            if 'scanner' in locals():
                print(f"{Fore.YELLOW}[!] Saving partial results...{Style.RESET_ALL}")
                if args.output:
                    print(f"{Fore.GREEN}[✓] URLs saved to: {args.output}{Style.RESET_ALL}")
                if args.savemeter:
                    scanner.save_all_endpoints_to_file()
                    print(f"{Fore.GREEN}[✓] Endpoints saved to: {args.savemeter}{Style.RESET_ALL}")
                scanner.print_results()
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving partial results: {str(e)}{Style.RESET_ALL}")

        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()
