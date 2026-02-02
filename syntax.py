#!/usr/bin/env python3
import argparse
import socket
import requests
import hashlib
import base64
import sys
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (SyntaxCommunity; Unrestricted Security Toolkit; Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def scan_port(target_ip, ports_str):
    print(f"[+] Memulai pemindaian port pada: {target_ip}")
    ports = range(1, 65536)
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.01)
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
        print("    [-] Tidak ada port yang terbuka ditemukan di antara 1-65535.")
    return open_ports

def check_header(target_url):
    print(f"[+] Memeriksa header untuk: {target_url}")
    try:
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            
        response = requests.get(target_url, timeout=10, allow_redirects=False, headers={'User-Agent': USER_AGENT})
        print(f"    [INFO] Status Code: {response.status_code}")
        print("    [HEADER RESPONSE]:")
        for key, value in response.headers.items():
            print(f"      {key}: {value}")
            
    except requests.exceptions.RequestException as e:
        print(f"    [ERROR] Gagal terhubung atau waktu habis: {e}")

def hash_data(data, algo):
    data_bytes = data.encode('utf-8')
    try:
        hasher = hashlib.new(algo)
        hasher.update(data_bytes)
        print(f"    [{algo.upper()} HASH]: {hasher.hexdigest()}")
    except ValueError:
        print(f"    [ERROR] Algoritma hashing '{algo}' tidak didukung. Coba: md5, sha1, sha256, sha512.")

def encode_base64(data):
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    print(f"    [BASE64 ENCODED]: {encoded_bytes.decode('utf-8')}")

def decode_base64(data):
    try:
        decoded_bytes = base64.b64decode(data)
        print(f"    [BASE64 DECODED]: {decoded_bytes.decode('utf-8')}")
    except Exception as e:
        print(f"    [ERROR] Gagal mendekode Base64. Pastikan input valid: {e}")

def crawl_for_subdomains(target_url, max_depth=1):
    print(f"[+] Memulai *crawling* (Depth: {max_depth}) untuk: {target_url}")
    
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
        
        visited.add(current_url)
        print(f"    [CRAWLING DEPTH {depth}]: {current_url}")

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
        print("\n    [Domain lain yang ditemukan]:")
        for sub in sorted(list(found_subdomains)):
            print(f"      -> {sub}")
    else:
        print("    [-] Domain tidak ditemukan, sepertinya target menggunakan WAF cloudflare.")

def scan_website_ips(url):
    print(f"[+] Mencari IP untuk: {url}")
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
            print(f"    [IP ADDRESSES DITEMUKAN]:")
            for ip in sorted(list(unique_ips)):
                print(f"      - {ip}")
        else:
            print("    [-] Tidak dapat menemukan alamat IP yang valid.")

    except socket.gaierror:
        print(f"    [ERROR] Resolusi DNS gagal untuk '{hostname}'.")
    except Exception as e:
        print(f"    [ERROR] Terjadi kesalahan: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Syntax-Seckit - Toolkit security berbasis CLI. Prefix Utama: syntax",
        epilog="Gunakan 'syntax <perintah> --help' untuk bantuan lebih lanjut pada setiap modul."
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # --- Perintah Port Scan ---
    parser_port = subparsers.add_parser('portscan', help='Memindai port pada IP target.')
    parser_port.add_argument('ip', help='Alamat IP target.')
    parser_port.add_argument('-p', '--ports', default='80,443', help='Daftar port yang akan dipindai (hanya untuk kompatibilitas lama, diabaikan untuk pemindaian penuh).')
    parser_port.set_defaults(func=lambda args: scan_port(args.ip, args.ports))

    # --- Perintah Header ---
    parser_header = subparsers.add_parser('header', help='Memeriksa header HTTP dari URL target.')
    parser_header.add_argument('url', help='URL target (misal: example.com atau https://example.com).')
    parser_header.set_defaults(func=lambda args: check_header(args.url))

    # --- Perintah Crawling ---
    parser_sub = subparsers.add_parser('crawl', help='Enumerator Subdomain berbasis *Crawling* tautan.')
    parser_sub.add_argument('url', help='URL awal untuk memulai *crawling* (misal: https://domain.com).')
    parser_sub.add_argument('--depth', type=int, default=1, help='Kedalaman *crawling* maksimum (Default: 1).')
    parser_sub.set_defaults(func=lambda args: crawl_for_subdomains(args.url, args.depth))

    # --- Perintah IP Scanner ---
    parser_ip = subparsers.add_parser('ipscan', help='Mendapatkan semua alamat IP yang terkait dengan nama host/URL.')
    parser_ip.add_argument('target', help='Target website/domain.')
    parser_ip.set_defaults(func=lambda args: scan_website_ips(args.target))

    # --- Perintah Hashing ---
    parser_hash = subparsers.add_parser('hash', help='Menghitung hash data.')
    parser_hash.add_argument('data', help='Data yang akan di-hash.')
    parser_hash.add_argument('-a', '--algorithm', default='sha256', help='Algoritma hashing (misal: md5, sha1, sha256, sha512). Default: sha256.')
    parser_hash.set_defaults(func=lambda args: hash_data(args.data, args.algorithm))

    # --- Perintah Base64 ---
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
        
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FATAL ERROR]: {e}")
        print("Pastikan Anda telah menginstal dependensi: 'pip install requests beautifulsoup4'")
        sys.exit(1)