#!/usr/bin/env python3
import argparse
import socket
import requests
import hashlib
import base64
import sys
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

USER_AGENT = "Syntax-Toolkit/4.5 (Unrestricted Security Toolkit; Linux) AppleWebKit/537.36"
MAX_PAGES = 20
visited_urls = set()
found_endpoints = []
url_queue = []
TARGET_URL_BASE = None

init(autoreset=True)

def is_internal_link(base_url, link_url):
    try:
        base_domain = urlparse(base_url).netloc
        link_domain = urlparse(link_url).netloc
        return link_domain == base_domain
    except:
        return False

def scan_port(target_ip, ports_str):
    print(f"{Fore.GREEN}Memulai pemindaian port pada {Fore.YELLOW}{target_ip}{Style.RESET_ALL}")
    ports = range(1, 65536)
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except OSError:
                service = "unknown"
            print(f"    [OPEN] Port {port}/{service}")
            open_ports.append(port)
        sock.close()    
    if not open_ports:
        print(f"    {Fore.RED}[-] {Fore.YELLOW}Tidak ada port yang terbuka ditemukan di antara 1-65535.{Style.RESET_ALL}")
    return open_ports

def check_header(target_url):
    print(f"{Fore.GREEN}Memeriksa header untuk: {Fore.YELLOW}{target_url}{Style.RESET_ALL}")
    try:
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            
        response = requests.get(target_url, timeout=10, allow_redirects=False, headers={'User-Agent': USER_AGENT})
        print(f"    {Fore.CYAN}[INFO] {Fore.YELLOW}Status Code: {Fore.GREEN}{response.status_code}{Style.RESET_ALL}")
        print(f"    {Fore.RED}[HEADER RESPONSE]{Style.RESET_ALL}")
        for key, value in response.headers.items():
            print(f"      {key}: {value}")
            
    except requests.exceptions.RequestException as e:
        print(f"    {Fore.RED}[ERROR] {Fore.YELLOW}Gagal terhubung atau waktu habis: {e}{Style.RESET_ALL}")

def extract_from_content(url, content):
    global visited_urls, found_endpoints
    
    if url in visited_urls or len(visited_urls) >= MAX_PAGES:
        return
    
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Memproses Konten dari: {Fore.YELLOW}{url}")
    visited_urls.add(url)

    try:
        soup = BeautifulSoup(content, 'html.parser')
    except Exception as e:
        print(f"  {Fore.RED}[ERROR]{Style.RESET_ALL} Gagal parsing HTML: {e}")
        return
            
    for link in soup.find_all('a', href=True):
        href = link['href']
        absolute_url = urljoin(url, href)
        clean_url = absolute_url.split('#')[0]                
        if is_internal_link(TARGET_URL_BASE, clean_url) and clean_url not in visited_urls:
            if clean_url not in url_queue:
                url_queue.append(clean_url)
            found_endpoints.append({"type": "link", "url": clean_url})
            
    for form in soup.find_all('form'):
        form_action = form.get('action', url)
        method = form.get('method', 'get').lower()
        form_url = urljoin(url, form_action)
        params = []

        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')

            if input_name:
                params.append(f"{input_name}({input_type})")
        form_details = {
            "type": "form",
            "url": form_url,
            "method": method,
            "parameters": ", ".join(params) if params else "Tidak ada parameter eksplisit ditemukan"
        }
        found_endpoints.append(form_details)

def crawl_website(target_url, max_depth=MAX_PAGES):
    global visited_urls, found_endpoints, url_queue, TARGET_URL_BASE
    
    visited_urls = set()
    found_endpoints = []
    url_queue = []
    TARGET_URL_BASE = target_url

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"{Fore.GREEN}Memulai crawling pada {Fore.YELLOW}{target_url}{Style.RESET_ALL}")
    url_queue.append(target_url)

    while url_queue and len(visited_urls) < max_depth:
        current_url = url_queue.pop(0)
        if current_url in visited_urls:
            continue
        
        try:
            print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Mengakses: {Fore.YELLOW}{current_url}{Style.RESET_ALL}")
            response = requests.get(current_url, timeout=30, headers={'User-Agent': USER_AGENT})
            
            if response.status_code == 200:
                extract_from_content(current_url, response.text)
            else:
                print(f"  {Fore.LIGHTRED_EX}[-]{Style.RESET_ALL} Gagal/Status Tidak OK: Status {response.status_code} untuk {current_url}")
        except requests.exceptions.RequestException as e:
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} Error Permintaan saat mengakses {Fore.YELLOW}{current_url}{Style.RESET_ALL}: {e}")            
            
    print(f"\n{Fore.BLUE}---===({Style.RESET_ALL} {Fore.YELLOW}HASIL PENGUMPULAN ENDPOINT & PARAMETER{Style.RESET_ALL} {Fore.BLUE})===---{Style.RESET_ALL}")
    
    unique_endpoints_map = {}
    for item in found_endpoints:
        key = (item['type'], item.get('url'), item.get('method'), item.get('parameters'))
        if key not in unique_endpoints_map:
            unique_endpoints_map[key] = item
            
    if not unique_endpoints_map:
        print(f"{Fore.YELLOW}Tidak ada endpoint yang ditemukan atau dikunjungi.")
    else:
        for item in unique_endpoints_map.values():
            if item['type'] == 'link':
                 print(f"{Fore.GREEN}[LINK]{Style.RESET_ALL} {item['url']}")
            elif item['type'] == 'form':
                method_color = Fore.RED if item['method'].lower() == 'post' else Fore.YELLOW
                print(f"{method_color}[FORM - {item['method'].upper()}]{Style.RESET_ALL} {item['url']}")
                print(f"    -> {Fore.WHITE}Params:{Style.RESET_ALL} {item['parameters']}")
                
    print(f"\n{Fore.MAGENTA}[INFO]{Style.RESET_ALL} Total URL yang Dikunjungi: {len(visited_urls)}")


def crawl_for_subdomains(target_url, max_depth=1):
    print(f"{Fore.CYAN}[*]{Fore.GREEN} Memulai crawling subdomain (Depth: {max_depth}) ke: {Fore.YELLOW}{target_url}{Style.RESET_ALL}")
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
        
    base_domain = urlparse(target_url).netloc
    found_subdomains = set()
    queue = [(target_url, 0)]
    visited = set()

    while queue:
        current_url, depth = queue.pop(0)
        
        if current_url in visited or depth > max_depth:
            continue
        
        try:
            response = requests.get(current_url, timeout=5, headers={'User-Agent': USER_AGENT})
            if response.status_code != 200:
                continue
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(current_url, href)
                parsed_url = urlparse(full_url)
                netloc = parsed_url.netloc
                
                if netloc and netloc != base_domain and '.' in netloc:
                    found_subdomains.add(netloc)
                    
                if parsed_url.netloc == base_domain and parsed_url.scheme in ('http', 'https'):
                    queue.append((full_url, depth + 1))

        except requests.exceptions.RequestException:
            continue

    if found_subdomains:
        print(f"\n    {Fore.RED}[Domain ditemukan]{Style.RESET_ALL}")
        for sub in sorted(list(found_subdomains)):
            print(f"      {Fore.GREEN}[+] {Style.RESET_ALL}{sub}")
    else:
        print(f"    {Fore.RED}[-] {Fore.YELLOW}Domain tidak ditemukan, sepertinya target menggunakan WAF cloudflare.{Style.RESET_ALL}")

def scan_website_ips(url):
    print(f"{Fore.GREEN}Mencari IP untuk {Fore.YELLOW}{url}{Style.RESET_ALL}")
    try:
        hostname = urlparse(url).netloc if urlparse(url).netloc else url
        if not hostname:
             hostname = url
             
        ip_addresses = socket.getaddrinfo(hostname, None)
        unique_ips = set()
        
        for res in ip_addresses:
            if res[0] == socket.AF_INET:
                unique_ips.add(res[4][0])
        
        if unique_ips:
            print(f"    {Fore.RED}[IP ADDRESSES DITEMUKAN]{Style.RESET_ALL}")
            for ip in sorted(list(unique_ips)):
                print(f"      - {ip}")
        else:
            print(f"    {Fore.RED}[-] {Fore.YELLOW}Tidak dapat menemukan alamat IP yang valid.{Style.RESET_ALL}")

    except socket.gaierror:
        print(f"    {Fore.RED}[ERROR] {Fore.YELLOW}Resolusi DNS gagal untuk '{hostname}'.{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}[ERROR] {Fore.YELLOW} Terjadi kesalahan: {e}{Style.RESET_ALL}")

def hash_data(data, algo):
    data_bytes = data.encode('utf-8')
    try:
        hasher = hashlib.new(algo)
        hasher.update(data_bytes)
        print(f"    [{Fore.GREEN}{algo.upper()} {Fore.CYAN}HASH{Style.RESET_ALL}]{Fore.RED}: {Fore.YELLOW}{hasher.hexdigest()}{Style.RESET_ALL}")
    except ValueError:
        print(f"    {Fore.RED}[ERROR] {Fore.GREEN}Algoritma hashing '{algo}' tidak didukung. {Fore.YELLOW}Coba: md5, sha1, sha256, sha512.{Style.RESET_ALL}")

def encode_base64(data):
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    print(f"    [{Fore.GREEN}BASE64 {Fore.CYAN}ENCODED{Style.RESET_ALL}]{Fore.RED}: {Fore.YELLOW}{encoded_bytes.decode('utf-8')}{Style.RESET_ALL}")

def decode_base64(data):
    try:
        decoded_bytes = base64.b64decode(data)
        print(f"    [{Fore.GREEN}BASE64 {Fore.CYAN}DECODED{Style.RESET_ALL}]{Fore.RED}: {Fore.YELLOW}{decoded_bytes.decode('utf-8')}{Style.RESET_ALL}")
    except Exception as e:
        print(f"    {Fore.RED}[ERROR] {Fore.GREEN}Gagal mendekode Base64. {Fore.YELLOW}Pastikan input valid: {Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="Syntax-Seckit V4.5 - Toolkit security berbasis CLI. Prefix Utama: syntax",
        epilog="Gunakan 'syntax <perintah> --help' untuk bantuan lebih lanjut pada setiap modul."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_port = subparsers.add_parser('portscan', help='Memindai port pada IP target.')
    parser_port.add_argument('ip', help='Alamat IP target.')
    parser_port.add_argument('-p', '--ports', default='80,443', help='[DIABAIKAN] Daftar port yang akan dipindai (Pemindaian penuh 1-65535 selalu dilakukan).')
    parser_port.set_defaults(func=lambda args: scan_port(args.ip, args.ports))

    parser_header = subparsers.add_parser('header', help='Memeriksa header HTTP dari URL target.')
    parser_header.add_argument('url', help='URL target (misal: example.com atau https://example.com).')
    parser_header.set_defaults(func=lambda args: check_header(args.url))
    
    parser_crawl = subparsers.add_parser('crawl', help='Crawler agresif untuk mengumpulkan link dan detail form.')
    parser_crawl.add_argument('url', help='URL awal untuk memulai *crawling* (misal: https://domain.com).')
    parser_crawl.add_argument('--max-pages', type=int, default=MAX_PAGES, help=f'Jumlah maksimum halaman untuk dikunjungi. Default: {MAX_PAGES}.')
    parser_crawl.set_defaults(func=lambda args: crawl_website(args.url, args.max_pages))

    parser_sub = subparsers.add_parser('subdomain', help='Enumerator Subdomain berbasis *Crawling* tautan.')
    parser_sub.add_argument('url', help='URL awal untuk memulai *crawling* (misal: https://domain.com).')
    parser_sub.add_argument('--depth', type=int, default=1, help='Kedalaman *crawling* maksimum (Default: 1).')
    parser_sub.set_defaults(func=lambda args: crawl_for_subdomains(args.url, args.depth))

    parser_ip = subparsers.add_parser('ipscan', help='Mendapatkan semua alamat IP yang terkait dengan nama host/URL.')
    parser_ip.add_argument('target', help='Target website/domain.')
    parser_ip.set_defaults(func=lambda args: scan_website_ips(args.target))

    parser_hash = subparsers.add_parser('hash', help='Menghitung hash data.')
    parser_hash.add_argument('data', help='Data yang akan di-hash.')
    parser_hash.add_argument('-a', '--algorithm', default='sha256', help='Algoritma hashing (misal: md5, sha1, sha256, sha512). Default: sha256.')
    parser_hash.set_defaults(func=lambda args: hash_data(args.data, args.algorithm))

    parser_b64 = subparsers.add_parser('base64', help='Melakukan encode/decode Base64.')
    group = parser_b64.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encode', action='store_true', help='Mengkodekan data.')
    group.add_argument('-d', '--decode', action='store_true', help='Mendekodekan data.')
    parser_b64.add_argument('data', help='Data yang akan diproses.')
    
    def base64_handler(args):
        if args.encode:
            encode_base64(args.data)
        elif args.decode:
            decode_base64(args.data)
            
    parser_b64.set_defaults(func=base64_handler)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args(sys.argv[1:])
        
    if hasattr(args, 'func'):
        args.func(args)

if __name__ == "__main__":
    
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR]: {e}")
        print("Pastikan Anda telah menginstal dependensi: 'pip install requests beautifulsoup4 colorama'")
        sys.exit(1)