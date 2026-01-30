# Syntax-SecKit

**Syntax-SecKit** adalah sebuah toolkit keamanan serbaguna yang dirancang untuk membantu pengujian keamanan dan audit sistem. Toolkit ini mencakup berbagai fungsi penting seperti pemindaian port, pemeriksaan header HTTP, crawling web, pemindaian IP, hashing, serta enkripsi dan dekripsi Base64.

## Fitur Utama

- 🔍 **Port Scanner**: Memindai port terbuka pada target host.
- 🕵️ **Header Checker**: Menganalisis header respons HTTP dari suatu situs web.
- 🕷️ **Web Crawler**: Menjelajahi struktur situs web untuk mengumpulkan informasi.
- 🌐 **IP Scanner**: Mendeteksi aktifitas dan informasi terkait alamat IP.
- #️⃣ **Hashing Tool**: Menghasilkan hash menggunakan berbagai algoritma (MD5, SHA1, SHA256, dll).
- 🔐 **Encode/Decode Base64**: Melakukan enkripsi dan dekripsi data dalam format Base64.

## Instalasi

```bash
git clone https://github.com/username/syntax-seckit.git
cd syntax-seckit
pip install -r requirements.txt
```

## Penggunaan

Setiap modul dapat dijalankan secara terpisah melalui CLI:

### Contoh Perintah

```bash
syntax portscan <target_ip>
syntax header <url>
syntax crawl <url>
syntax ipscan <url>
syntax hasher <text/number>
syntax base64_tool.py -e <string>
syntax base64_tool.py -d <encoded_string>
```

## Lisensi

Proyek ini dilisensikan di bawah lisensi MIT. Lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.

---

Dibuat oleh Syntax Commmunity.