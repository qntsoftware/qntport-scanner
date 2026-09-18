<!-- ========================================================= -->
<!--                    QNTSOFTWARE - PORTER                    -->
<!--         Advanced Network Analysis & Security Scanner       -->
<!-- ========================================================= -->

<div align="center">

# 🛰️ QNTSOFTWARE — Port SCANNER

### Advanced Network Analysis & Security Scanning Tool

![Project Name](https://img.shields.io/badge/PROJECT%20NAME-QNTSOFTWARE-red?style=for-the-badge)
![Build](https://img.shields.io/badge/BUILD-PASSING-brightgreen?style=for-the-badge)
![Version](https://img.shields.io/badge/VERSION-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/LICENSE-MIT-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/PLATFORM-WINDOWS%20%7C%2010%2611-lightgrey?style=for-the-badge)
![Python](https://img.shields.io/badge/PYTHON-3.6%2B-yellow?style=for-the-badge&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/STATUS-ACTIVE-success?style=for-the-badge)
![Made With](https://img.shields.io/badge/MADE%20WITH-PYTHON-3776AB?style=for-the-badge&logo=python&logoColor=white)

<img width="1920" height="1080" alt="QNTSOFTWARE-Porter Preview" src="https://i.hizliresim.com/ee4uvdco.png" />

</div>

---

## 📌 Kısa Açıklama

> **QNTSOFTWARE-Porter**, port taraması yaparak hedef IP üzerindeki açıkları, açık portlarda çalışan servisleri, **proxy servislerini** ve **IP içinde saklanan gizli URL'leri / IP'leri** tespit eden kapsamlı bir Python tabanlı ağ güvenliği aracıdır.

---

## 🚀 Çalıştırma

Komut satırında dosya yoluna gidin ve şu komutu girin:

```bash
python qntport.py
```

---

## 📚 İçindekiler

- [Tanım](#-tanım)
- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Komut Satırı Argümanları](#-komut-satırı-argümanları)
- [Örnek Kullanım ve Sonuçlar](#-örnek-kullanım-ve-sonuçlar)
- [Raporlama](#-raporlama)
- [Gereksinimler](#-gereksinimler)
- [Ekran Görüntüleri](#-ekran-görüntüleri)
- [SSS](#-sıkça-sorulan-sorular-sss)
- [Lisans](#-lisans)
- [Yasal Uyarı](#-yasal-uyarı)

---

## 📖 Tanım

**QNTSOFTWARE**, ağ güvenliği testleri ve ağ analizi için geliştirilmiş kapsamlı bir Python tabanlı güvenlik aracıdır. Port tarama, zafiyet tespiti, proxy tespiti ve ağ keşfi gibi birçok fonksiyonu bünyesinde barındırır.

---

## ✨ Özellikler

<details>
<summary><b>1. 🔍 Port Tarama</b></summary>

- TCP Connect taraması
- SYN taraması (gizli tarama için)
- UDP taraması
- Belirlenen port aralığında tarama
- Belirli portlarda tarama (örnek: `22,80,443`)
- Çoklu thread desteği (varsayılan: 200 thread)
- Zaman aşımı kontrolü

</details>

<details>
<summary><b>2. 🛡️ Proxy Tespiti</b></summary>

- Açık portlarda çalışan proxy servislerini tespit eder
- HTTP proxy tespiti
- Proxy servislerini doğrular ve raporlar
- Port taraması sırasında otomatik proxy algılama

</details>

<details>
<summary><b>3. 🌐 Ağ Keşfi</b></summary>

- Hedef IP adresinin ait olduğu ağ aralığını belirler
- Ağda aktif olan diğer IP adreslerini keşfeder
- Ağ geçidini tahmin eder
- DNS bilgilerini gösterir

</details>

<details>
<summary><b>4. 🐞 Zafiyet Taraması</b></summary>

- Açık portlarda çalışan servisler için güvenlik açıklarını tespit eder
- SSH, FTP, Web servisleri gibi yaygın servislerdeki açıkları tarar
- Anonymous FTP erişimi gibi yaygın zafiyetleri bulur

</details>

<details>
<summary><b>5. 🌍 Web Taraması</b></summary>

- Web sitelerinde güvenlik açıklarını tespit eder
- Eksik güvenlik başlıklarını (security headers) bulur
- Hassas dizinleri ve dosyaları tarar

</details>

<details>
<summary><b>6. 📦 Paket Analizi</b></summary>

- PCAP dosyaları üzerinden ağ trafiğini analiz eder
- Şüpheli aktiviteleri tespit eder
- Ağ protokolleri ve IP istatistiklerini gösterir

</details>

<details>
<summary><b>7. 📡 Kablosuz Ağ Taraması</b></summary>

- WiFi ağlarını tarar
- SSID, BSSID, kanal ve şifreleme bilgilerini gösterir

</details>

<details>
<summary><b>8. 🧠 IP İçinde Saklı URL / IP Tespiti</b></summary>

- Hedef IP içinde gizlenmiş URL'leri ortaya çıkarır
- Gizli IP adreslerini listeler
- Banner ve yanıt gövdesi içinde gömülü adresleri analiz eder

</details>

---

## 🛠️ Kurulum

### 1) Python Kurulumu

Python **3.6 veya üzeri** bir sürüm gereklidir.

```bash
python --version
```

### 2) Depoyu Klonlayın

```bash
git clone https://github.com/<kullanici-adiniz>/QNTSOFTWARE-Porter.git
cd QNTSOFTWARE-Porter
```

### 3) (Önerilen) Sanal Ortam Oluşturun

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 4) Gerekli Kütüphaneleri Yükleyin

```bash
pip install scapy paramiko dnspython requests netifaces
```

veya tek satırda:

```bash
pip install -r requirements.txt
```

---

## 🎯 Kullanım

### Temel Kullanım

```bash
python qntport.py <hedef>
```

### Port Tarama

```bash
# Belirli port aralığında tarama
python qntport.py 192.168.1.1 -p 1-1000

# Belirli portlarda tarama
python qntport.py 192.168.1.1 -p 22,80,443

# SYN taraması (yönetici/root yetkisi gerekir)
python qntport.py 192.168.1.1 -p 1-1000 -t syn

# UDP taraması
python qntport.py 192.168.1.1 -p 53,137 -t udp
```

### Gelişmiş Tarama

```bash
# Tüm tarama türlerini çalıştır
python qntport.py --advanced 192.168.1.1

# Ağ taraması
python qntport.py --network-scan 192.168.1.0/24

# Web taraması
python qntport.py --web-scan example.com

# Kablosuz ağ taraması
python qntport.py --wireless-scan

# PCAP dosyası analizi
python qntport.py --packet-analysis --pcap-file capture.pcap
```

### Çıktı Formatları

```bash
# JSON çıktı
python qntport.py 192.168.1.1 --json -o sonuc.json

# CSV çıktı
python qntport.py 192.168.1.1 --csv -o sonuc.csv

# Metin raporu
python qntport.py 192.168.1.1 -o rapor.txt
```

---

## 🧾 Komut Satırı Argümanları

| Argüman | Açıklama | Varsayılan |
|---------|----------|------------|
| `target` | Hedef IP, hostname veya ağ | — |
| `-p, --ports` | Taranacak port aralığı | `1-1000` |
| `-t, --scan-type` | Tarama tipi (`tcp`, `syn`, `udp`, `all`) | `tcp` |
| `--threads` | Thread sayısı | `200` |
| `--timeout` | Zaman aşımı (saniye) | `1` |
| `--ping` | Ping taraması yap | `false` |
| `--sniff` | Paket dinleme modu | `false` |
| `-i, --interface` | Ağ arayüzü | otomatik |
| `-c, --count` | Dinlenecek paket sayısı | — |
| `--vuln-scan` | Güvenlik açığı taraması yap | `false` |
| `-o, --output` | Çıktı dosyası | otomatik |
| `--json` | JSON formatında çıktı | `false` |
| `--csv` | CSV formatında çıktı | `false` |
| `--advanced` | Gelişmiş tarama | `false` |
| `--network-scan` | Ağ taraması | `false` |
| `--web-scan` | Web taraması | `false` |
| `--wireless-scan` | Kablosuz tarama | `false` |
| `--packet-analysis` | Paket analizi | `false` |
| `--pcap-file` | PCAP dosyası analizi | — |

---

## 📊 Örnek Kullanım ve Sonuçlar

### Örnek 1: Temel Port Taraması

```bash
python qntport.py 192.168.1.1 -p 22,80,443
```

**Çıktı:**

```
QNTSOFTWARE TARAMA RAPORU
===========================================================

Hedef: 192.168.1.1
Tarama Zamani: 2025-12-28T12:54:42.326329
Hostname: ADSL
OS Tahmini: Linux/Unix

Istatistikler:
  Taranan Port: 3
  Acik Port: 1
  Sure: 7.74 seconds
  Tespit Edilen Guvenlik Aciklari: 4

AĞ ANALİZİ:
  Ağ Aralığı: 192.168.1.0/24
  Ağ Geçidi: 192.168.1.1
  Keşfedilen Hostlar: 7
    - 192.168.1.1
    - 192.168.1.110
    - 192.168.1.102
    - 192.168.1.108
    - 192.168.1.109
    - 192.168.1.103
    - 192.168.1.107

ACIK PORTLAR:
Port    Protokol        Servis          Banner              Proxy
---------------------------------------------------------
80      tcp             http            HTTP/1.1 400 Bad    HTTP Proxy: 192.168.1.1:80
Request
Cont...
```

### Örnek 2: Proxy Tespiti

Açık portlarda çalışan proxy servisleri otomatik olarak tespit edilir ve raporda **"Proxy"** sütununda gösterilir.

### Örnek 3: Ağ Keşfi

Hedef IP adresi verildiğinde, program o IP'nin ait olduğu ağ aralığını belirler ve ağda aktif olan diğer IP adreslerini tarar.

---

## 📄 Raporlama

### Metin Dosyası Raporu

Program, tarama sonuçlarını otomatik olarak metin dosyasına kaydeder. Dosya adı formatı:

```
qntsoftware_scan_<hedef>_<tarih_saat>.txt
```

### Rapor İçeriği

- Hedef bilgileri
- Ağ analiz sonuçları
- Açık portlar ve servis bilgileri
- Banner bilgileri
- Proxy bilgileri
- Tespit edilen güvenlik açıkları
- Ağ keşfi sonuçları

---

## 📋 Gereksinimler

- Python 3.6 veya üzeri
- Aşağıdaki Python kütüphaneleri:
  - `scapy`
  - `paramiko`
  - `dnspython`
  - `requests`
  - `netifaces`

---

## 🖼️ Ekran Görüntüleri

### Ana Arayüz (CLI)

<img width="1920" height="1080" alt="QNTSOFTWARE-Porter CLI" src="https://i.hizliresim.com/ee4uvdco.png" />

### VirusTotal Sonuçları

<img width="1858" height="957" alt="VirusTotal Sonuçları" src="https://github.com/user-attachments/assets/72d654df-08cb-4d6b-ad1e-475bb16b2af0" />

---

## ❓ Sıkça Sorulan Sorular (SSS)

<details>
<summary><b>QNTSOFTWARE-Porter yasal mı?</b></summary>

Bu araç yalnızca **eğitim** ve **yetkili güvenlik testleri** için tasarlanmıştır. İzinsiz sistemlerde kullanmak yasa dışıdır. Kullanıcı, aracın kullanımından doğacak tüm sorumluluğu kabul eder.

</details>

<details>
<summary><b>Hangi işletim sistemlerinde çalışır?</b></summary>

Windows 10/11, Linux ve macOS üzerinde çalışır. SYN taraması ve paket dinleme için yönetici/root yetkisi gerekebilir.

</details>

<details>
<summary><b>Proxy tespiti nasıl çalışır?</b></summary>

Açık portlara HTTP istekleri gönderilir ve yanıt başlıkları incelenerek proxy davranışı olup olmadığı anlaşılır. Tespit edilen proxy'ler rapora eklenir.

</details>

<details>
<summary><b>IP içinde saklı URL'ler nasıl bulunur?</b></summary>

Banner bilgileri, HTTP yanıt gövdeleri ve servis çıktıları düzenli ifadelerle taranarak gömülü URL'ler ve IP adresleri çıkarılır.

</details>

<details>
<summary><b>Raporlar nereye kaydedilir?</b></summary>

Varsayılan olarak çalışma dizinine `qntsoftware_scan_<hedef>_<tarih_saat>.txt` formatında kaydedilir. `-o` parametresi ile özel yol belirtilebilir.

</details>

---

## ⚖️ Lisans

Bu proje **MIT Lisansı** altında açık kaynaklıdır ve eğitim amaçlı kullanılabilir.

---

## ⚠️ Yasal Uyarı

Bu araç yalnızca **eğitim** ve **yetkili güvenlik testleri** için tasarlanmıştır. İzinsiz sistemlerde kullanmak yasa dışıdır. Kullanıcı, aracın kullanımından doğacak tüm sorumluluğu kabul eder. Geliştirici hiçbir kötüye kullanımdan sorumlu tutulamaz.

---

<div align="center">

**⭐ Projeyi beğendiyseniz yıldız vermeyi unutmayın! ⭐**

</div>
