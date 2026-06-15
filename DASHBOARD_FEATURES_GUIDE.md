# DOKUMENTASI & PANDUAN INTEGRASI FITUR MASANDIGITAL DASHBOARD

Dokumen ini berisi panduan lengkap, spesifikasi arsitektur, dan cara kerja dari seluruh fitur premium yang telah kita pasang dan konfigurasi pada Masandigital Dashboard. Simpan dokumen ini sebagai referensi utama untuk instalasi ulang server di masa mendatang.

---

## 📋 DAFTAR ISI
1. [Fitur 1: Web Package Manager (System Updates)](#fitur-1-web-package-manager-system-updates)
2. [Fitur 2: Wake-on-LAN (WOL) Controller](#fitur-2-wake-on-lan-wol-controller)
3. [Fitur 3: UPnP Router Port Forwarding Mapper](#fitur-3-upnp-router-port-forwarding-mapper)
4. [Fitur 4: GeoIP Live Visitor Map](#fitur-4-geoip-live-visitor-map)
5. [Fitur 5: Perbaikan Terminal Interaktif (Keyboard Freeze Fix)](#fitur-5-perbaikan-terminal-interaktif-keyboard-freeze-fix)
6. [Fitur 6: Task Manager (Process Killer)](#fitur-6-task-manager-process-killer)
7. [Fitur 7: iOS Sync (WebDAV) & Solusi Integrasi iPhone](#fitur-7-ios-sync-webdav--solusi-integrasi-iphone)
8. [Panduan Tambahan: Setup Immich Media Backup](#panduan-tambahan-setup-immich-media-backup)

---

## 1. Fitur 1: Web Package Manager (System Updates)
Fitur ini memungkinkan administrator memindai daftar paket sistem operasi host yang dapat ditingkatkan (upgradable) dan menjalankan pembaruan (`apt-get upgrade`) secara aman dari latar belakang dengan keluaran konsol secara real-time.

### Cara Kerja & Arsitektur
* **Pindai Paket**: Backend memanggil perintah `nsenter -t 1 -m -u -i -n -p apt-get update` lalu mengurai output dari `apt-get --just-print upgrade` untuk mendeteksi paket yang tersedia.
* **Upgrade Real-time**: Menggunakan sub-proses background Python yang dijalankan melalui Flask-SocketIO. Log keluaran dari perintah `apt-get upgrade -y` dibaca baris demi baris dan dipancarkan ke frontend melalui event `pkg_upgrade_log`.
* **Keamanan**: Perintah dibatasi hanya untuk user dengan role admin (`@requires_permission('terminal')`).

### Komponen File
* **Backend**: `app.py` -> Route `/api/packages/updates` dan `/api/packages/upgrade`
* **Frontend**: `templates/pkg_manager.html`

---

## 2. Fitur 2: Wake-on-LAN (WOL) Controller
Fitur untuk menyalakan komputer lain dalam satu jaringan lokal (LAN) secara instan dengan mengirimkan paket sinyal siaran (Magic Packet).

### Cara Kerja & Arsitektur
* **Penyimpanan Data**: Daftar perangkat disimpan dalam berkas JSON lokal di `data/wol_devices.json`.
* **Magic Packet**: Protokol UDP siaran (broadcast) dikirim ke alamat IP `255.255.255.255` pada Port 7 dan 9. Magic packet terdiri dari 6 byte bernilai `0xFF` diikuti oleh alamat MAC target yang diulang sebanyak 16 kali.
* **Kode Python**:
  ```python
  import socket
  # Mengonversi alamat MAC menjadi byte heksadesimal
  mac_bytes = bytes.fromhex(mac_address.replace(':', '').replace('-', ''))
  magic_packet = b'\xff' * 6 + mac_bytes * 16
  
  # Mengirim via UDP Broadcast
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
      s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
      s.sendto(magic_packet, ('255.255.255.255', 9))
  ```

### Komponen File
* **Backend**: `app.py` -> Route `/api/wol/devices`, `/api/wol/devices/add`, `/api/wol/devices/remove`, dan `/api/wol/send`
* **Frontend**: `templates/wol.html`

---

## 3. Fitur 3: UPnP Router Port Forwarding Mapper
Fitur untuk membuka port akses luar (WAN) modem/router secara otomatis langsung dari dalam dashboard tanpa perlu masuk ke panel konfigurasi modem (seperti IndiHome/ISP lainnya).

### Cara Kerja & Arsitektur
* **Protokol SSDP**: Backend mengirimkan paket UDP pencarian SSDP (`239.255.255.250:1900`) untuk mencari router yang mengaktifkan fitur UPnP (layanan `WANIPConnection:1`).
* **SOAP/XML Request**: Setelah router terdeteksi, backend mengirimkan instruksi berupa SOAP XML request untuk melakukan pemetaan port (`AddPortMapping`) atau menghapus pemetaan (`DeletePortMapping`).
* **Kebutuhan Sistem**: Fitur UPnP wajib diaktifkan pada halaman admin modem/router Anda.

### Komponen File
* **Backend**: `app.py` -> Fungsi `get_upnp_control_url()`, `upnp_add_port_mapping()`, `upnp_delete_port_mapping()`, dan API routes `/api/upnp/*`
* **Frontend**: `templates/upnp.html`

---

## 4. Fitur 4: GeoIP Live Visitor Map
Menampilkan lokasi geografis (negara, kota, koordinat koordinat peta) dari seluruh pengunjung yang mengakses web server Anda secara interaktif menggunakan peta berbasis Leaflet.js.

### Cara Kerja & Arsitektur
* **Analisis Log**: Backend membaca berkas access log Nginx `/var/log/nginx/access.log` pada host OS (melalui akses `nsenter`) dan mengambil 250 IP pengunjung luar terakhir menggunakan ekspresi reguler (Regex).
* **GeoIP Lookup**: IP Publik pengunjung dikirim ke API `ip-api.com` untuk diterjemahkan menjadi koordinat Latitude, Longitude, Nama Negara, dan Kota.
* **Caching**: Untuk menghemat kuota limit API dan mempercepat performa, hasil lookup IP disimpan dalam cache lokal di `data/geoip_cache.json`.
* **Peta Interaktif**: Frontend (`templates/geoip_map.html`) memuat pustaka peta Leaflet.js dengan tema gelap (*CartoDB Dark Matter*) untuk memplot marker lokasi secara visual.

### Komponen File
* **Backend**: `app.py` -> Route `/api/geoip/visitors` dan helper lookup.
* **Frontend**: `templates/geoip_map.html`

---

## 5. Fitur 5: Perbaikan Terminal Interaktif (Keyboard Freeze Fix)
Sebelumnya, modul terminal web pada dashboard sering mengalami hang/beku (tidak bisa mengetik) karena penggunaan pustaka `select.select` bawaan python yang bertabrakan dengan monkey-patching hijau dari `eventlet`.

### Penyelesaian Arsitektur
* **Non-Blocking I/O**: Kita mengganti polling berbasis `select.select` dengan konfigurasi flag non-blocking pada file descriptor master PTY menggunakan modul `fcntl`:
  ```python
  import fcntl
  fl = fcntl.fcntl(fd, fcntl.F_GETFL)
  fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
  ```
* **Yield Execution**: Membaca keluaran PTY menggunakan pembacaan non-blocking murni dan memberikan jeda kecil `eventlet.sleep(0.02)` jika tidak ada data yang masuk (menghindari penggunaan CPU tinggi/busy spin).
* **Windows Developer Guard**: Menambahkan pengaman agar server dashboard dapat dijalankan di laptop Windows Anda untuk kebutuhan pengembangan tanpa merusak kode PTY Linux.

---

## 6. Fitur 6: Task Manager (Process Killer)
Memungkinkan pemantauan penggunaan CPU/RAM dari setiap proses yang berjalan pada sistem operasi Host (bukan hanya di dalam kontainer Docker) dan mematikan paksa proses yang bermasalah.

### Cara Kerja & Arsitektur
* **Akses Ruang Kerja Host**: Berkat konfigurasi `pid: host` pada `docker-compose.yml`, kontainer dashboard dapat melihat seluruh proses di server utama.
* **Process Kill**: Ketika tombol "Kill" ditekan pada halaman Metrics, API `/api/process/kill` akan memicu pembunuhan proses menggunakan perintah `nsenter -t 1 -m -u -i -n -p kill -9 <PID>`. Jika gagal, aplikasi akan melakukan fallback ke `os.kill(pid, 9)` lokal.

---

## 7. Fitur 7: iOS Sync (WebDAV) & Solusi Integrasi iPhone
WebDAV digunakan untuk menyinkronkan data aplikasi pihak ketiga (seperti Enpass, KeePass, Obsidian, dll.) antara server dan perangkat seluler (iPhone/iPad).

### Konfigurasi & Cara Kerja
* **Server**: Menggunakan pustaka python `wsgidav` yang berjalan secara asinkron dalam thread tersendiri melalui web server `cheroot` pada Port `5005` (default).
* **Kendala iOS Bawaan**: Aplikasi bawaan "Files" di iPhone **tidak mendukung** protokol WebDAV secara langsung melalui menu *Connect to Server* (menu tersebut hanya mendukung **SMB**).
* **Solusi Hubungkan**:
  1. **Melalui Aplikasi Sync**: Masukkan alamat `http://IP_SERVER:5005` langsung di dalam menu konfigurasi sync aplikasi (seperti Obsidian/Enpass).
  2. **Melalui File Manager Alternatif**: Gunakan aplikasi gratis dari App Store seperti **Documents by Readdle** atau **Owlfiles** untuk membuka koneksi WebDAV.
  3. **Gunakan Jalur HTTPS**: iOS memblokir HTTP biasa demi keamanan. Sangat disarankan mengarahkan subdomain HTTPS (contoh: `https://dav.domain.com`) melalui **Cloudflare Tunnel** mengarah ke `localhost:5005`.

---

## 8. Panduan Tambahan: Setup Immich Media Backup
Immich adalah alternatif Google Photos self-hosted terbaik untuk mencadangkan seluruh foto dan video dari iPhone Anda ke server pribadi secara otomatis.

### Langkah Instalasi di Server
1. Buat folder baru:
   ```bash
   mkdir ~/immich && cd ~/immich
   ```
2. Buat file `.env`:
   ```env
   UPLOAD_LOCATION=./library
   DB_PASSWORD=gantipassworddbanda
   DB_USERNAME=postgres
   DB_DATABASE_NAME=immich
   ```
3. Buat file `docker-compose.yml` (isi file lengkap lihat pada instruksi chat sebelumnya).
4. Jalankan kontainer:
   ```bash
   docker compose up -d
   ```
5. Akses `http://IP_SERVER:2283` untuk membuat akun administrator.
6. Unduh aplikasi **Immich** di iPhone dari App Store, lalu sambungkan ke alamat `http://IP_SERVER:2283/api`.

---
*Dokumen ini dibuat secara otomatis untuk membantu mempermudah penataan ulang server Masandigital Dashboard di masa mendatang.*
