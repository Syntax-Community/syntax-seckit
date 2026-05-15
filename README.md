# Syntax-SecKit v4.5

Toolkit pentesting & security audit berbasis CLI yang powerful dan mudah digunakan.

## Fitur

**Network & Infrastructure:**
- Port Scanner - Scan port penting pada target IP
- IP Scanner - Resolve hostname ke IP addresses
- DNS Enumeration - Enumerate DNS records (A, MX, NS, TXT, CNAME, SOA)
- SSL Certificate Checker - Lihat detail SSL/TLS certificate

**Web & Application:**
- Web Crawler - Crawl website untuk mengumpulkan links, forms & endpoints
- Header Checker - Analisis HTTP response headers
- Subdomain Enumeration - Cari subdomain melalui link crawling
 - Subdomain Enumeration - Cari subdomain melalui link crawling

**Utility:**
- Hash Generator - MD5, SHA1, SHA256, SHA512
- Base64 Encoder/Decoder - Encode & decode Base64 data

## Instalasi

```bash
git clone https://github.com/username/syntax-seckit.git
cd syntax-seckit
pip install -r requirements.txt
```

## Perintah Lengkap

### Network & Infrastructure
```
python syntax.py ipscan <domain>              # Resolve IP dari domain
python syntax.py portscan <ip>                # Scan port penting pada IP
python syntax.py dns <domain>                 # Enumerate DNS records
python syntax.py ssl <url>                    # Check SSL certificate info
```

### Web & Application
```
python syntax.py header <url>                 # Check HTTP response headers
python syntax.py crawl <url> [--max-pages N]  # Crawl website (default: 20 halaman)
python syntax.py subdomain <url> [--depth N]  # Find subdomains via crawling
python syntax.py dork <filename> <filetype>   # Dork search
# For path discovery and vulnerability analysis use `crawl` then manual testing
```

### Utility
```
python syntax.py hash <data> [-a ALGO]        # Hash data (default: sha256)
python syntax.py base64 <data> -e             # Encode Base64
python syntax.py base64 <data> -d             # Decode Base64
```

## Contoh Penggunaan

```bash
python syntax.py ipscan example.com
python syntax.py portscan 192.168.1.1
python syntax.py dns example.com
python syntax.py ssl https://example.com
python syntax.py header https://example.com
python syntax.py crawl https://example.com --max-pages 30
python syntax.py hash "mypassword" -a sha256
python syntax.py base64 "hello world" -e
python syntax.py base64 "aGVsbG8gd29ybGQ=" -d
```

## Lisensi

MIT License - Lihat [LICENSE](LICENSE) untuk detail
