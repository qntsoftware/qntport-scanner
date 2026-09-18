#!/usr/bin/env python3

import socket
import threading
import time
import subprocess
import sys
import os
import json
import csv
import argparse
import ipaddress
from datetime import datetime
from collections import defaultdict, Counter
import random
import struct
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urljoin
import ssl
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
import netifaces
import urllib.request

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

class Logger:
    
    COLORS = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'RESET': '\033[0m'
    }
    
    def __init__(self, log_file="qnt_scan.log"):
        self.log_file = log_file
        self.setup_logging()
    
    def setup_logging(self):
        with open(self.log_file, 'w') as f:
            f.write(f"QNT Scan Log - {datetime.now()}\n")
            f.write("=" * 50 + "\n")
    
    def log(self, message, level="INFO", color=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        if color and color in self.COLORS:
            print(f"{self.COLORS[color]}{log_entry}{self.COLORS['RESET']}")
        else:
            print(log_entry)
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry + "\n")
    
    def info(self, message):
        self.log(message, "INFO", "BLUE")
    
    def success(self, message):
        self.log(message, "SUCCESS", "GREEN")
    
    def warning(self, message):
        self.log(message, "WARNING", "YELLOW")
    
    def error(self, message):
        self.log(message, "ERROR", "RED")
    
    def critical(self, message):
        self.log(message, "CRITICAL", "MAGENTA")

class NetworkUtils:
    
    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def get_network_interfaces():
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interfaces.append({
                            'interface': interface,
                            'ip': addr.get('addr'),
                            'netmask': addr.get('netmask')
                        })
        except:
            pass
        return interfaces
    
    @staticmethod
    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    @staticmethod
    def hostname_to_ip(hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None
    
    @staticmethod
    def get_service_name(port, protocol='tcp'):
        try:
            return socket.getservbyport(port, protocol)
        except:
            return "unknown"

class PortScanner:
    
    def __init__(self, logger, timeout=1, max_threads=200):
        self.logger = logger
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.scan_results = defaultdict(dict)
        self.proxy_scanner = ProxyScanner(logger)
        self.network_discovery = NetworkDiscovery(logger)
    
    def tcp_connect_scan(self, target, ports):
        self.logger.info(f"TCP Connect taraması başlatılıyor: {target}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = NetworkUtils.get_service_name(port)
                    banner = self.get_banner(target, port)
                    return port, "open", service, banner
                else:
                    return port, "closed", "", ""
            except Exception as e:
                return port, "error", "", str(e)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            
            for future in as_completed(futures):
                port, status, service, banner = future.result()
                # Store all results, not just open ports
                self.scan_results[port] = {
                    'status': status,
                    'service': service,
                    'banner': banner,
                    'protocol': 'tcp'
                }
                if status == "open":
                    self.open_ports.append(port)
                    # Check if this open port is also a proxy
                    proxy_info = self.proxy_scanner.check_proxy(target, port)
                    if proxy_info:
                        self.scan_results[port]['proxy'] = proxy_info
                        self.logger.success(f"TCP {port} açık - {service} - {banner} - {proxy_info}")
                    else:
                        self.logger.success(f"TCP {port} açık - {service} - {banner}")
                elif status == "closed":
                    self.logger.info(f"TCP {port} kapalı")
                else:
                    self.logger.warning(f"TCP {port} hata: {banner}")
        
        return self.scan_results
    
    def syn_scan(self, target, ports):
        if not SCAPY_AVAILABLE:
            self.logger.error("SYN taraması için scapy gerekli!")
            return {}
        
        self.logger.info(f"SYN taraması başlatılıyor: {target}")
        
        def syn_scan_port(port):
            try:
                pkt = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(pkt, timeout=self.timeout, verbose=0)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:
                        sr(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                        service = NetworkUtils.get_service_name(port)
                        return port, "open", service, ""
                    elif response[TCP].flags == 0x14:
                        return port, "closed", "", ""
                return port, "filtered", "", ""
            except Exception as e:
                return port, "error", "", str(e)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(syn_scan_port, port) for port in ports]
            
            for future in as_completed(futures):
                port, status, service, _ = future.result()
                # Store all results
                self.scan_results[port] = {
                    'status': status,
                    'service': service,
                    'banner': "",
                    'protocol': 'tcp'
                }
                if status == "open":
                    self.open_ports.append(port)
                    # Check if this open port is also a proxy
                    proxy_info = self.proxy_scanner.check_proxy(target, port)
                    if proxy_info:
                        self.scan_results[port]['proxy'] = proxy_info
                        self.logger.success(f"TCP {port} açık - {service} (SYN) - {proxy_info}")
                    else:
                        self.logger.success(f"TCP {port} açık - {service} (SYN)")
                elif status == "closed":
                    self.logger.info(f"TCP {port} kapalı (SYN)")
                elif status == "filtered":
                    self.logger.info(f"TCP {port} filtrelenmiş (SYN)")
                else:
                    self.logger.warning(f"TCP {port} hata (SYN): {_}")
        
        return self.scan_results
    
    def udp_scan(self, target, ports):
        self.logger.info(f"UDP taraması başlatılıyor: {target}")
        
        def udp_scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b"", (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    service = NetworkUtils.get_service_name(port, 'udp')
                    return port, "open", service, data.decode('utf-8', errors='ignore')
                except socket.timeout:
                    return port, "open|filtered", "", ""
            except Exception as e:
                return port, "error", "", str(e)
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, 100)) as executor:
            futures = [executor.submit(udp_scan_port, port) for port in ports]
            
            for future in as_completed(futures):
                port, status, service, banner = future.result()
                # Store all results
                self.scan_results[port] = {
                    'status': status,
                    'service': service,
                    'banner': banner,
                    'protocol': 'udp'
                }
                if "open" in status:
                    # Check if this open port is also a proxy
                    proxy_info = self.proxy_scanner.check_proxy(target, port)
                    if proxy_info:
                        self.scan_results[port]['proxy'] = proxy_info
                        self.logger.success(f"UDP {port} {status} - {service} - {proxy_info}")
                    else:
                        self.logger.success(f"UDP {port} {status} - {service}")
                elif status == "closed":
                    self.logger.info(f"UDP {port} kapalı")
                else:
                    self.logger.warning(f"UDP {port} hata: {banner}")
        
        return self.scan_results
    
    def get_banner(self, target, port):
        try:
            socket.setdefaulttimeout(self.timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            
            if port in [21, 22, 23, 25, 80, 110, 143, 443, 993, 995]:
                # Send a small amount of data to potentially trigger a response
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner[:100]
        except Exception as e:
            # Log the error for debugging but don't expose it to the user
            pass
        finally:
            try:
                sock.close()
            except:
                pass
        return ""

class VulnerabilityScanner:
    
    def __init__(self, logger):
        self.logger = logger
        self.vulnerabilities = []
    
    def scan_common_vulnerabilities(self, target, port, service):
        self.logger.info(f"{target}:{port} için güvenlik taraması yapılıyor...")
        
        if port == 22 and service == 'ssh':
            self.check_ssh_vulnerabilities(target, port)
        
        elif port in [80, 443, 8080, 8443]:
            self.check_web_vulnerabilities(target, port)
        
        elif port == 21 and service == 'ftp':
            self.check_ftp_anonymous(target, port)
    
    def check_ssh_vulnerabilities(self, target, port):
        if not PARAMIKO_AVAILABLE:
            return
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            transport = paramiko.Transport((target, port))
            transport.connect()
            
            # Get server key info safely
            try:
                server_key = transport.get_remote_server_key()
                key_type = server_key.get_name()
                key_size = server_key.get_bits()
                
                if key_size < 2048:
                    self.vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'service': 'ssh',
                        'vulnerability': 'Weak SSH Key',
                        'severity': 'MEDIUM',
                        'description': f'SSH key size is only {key_size} bits'
                    })
                    self.logger.warning(f"Zayıf SSH anahtarı tespit edildi: {key_size} bit")
            except Exception as e:
                # Handle case where we can't get key info
                pass
            
            transport.close()
        except Exception as e:
            pass
    
    def check_web_vulnerabilities(self, target, port):
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{target}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            security_checks = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Strict-Transport-Security': 'HSTS header missing',
                'Content-Security-Policy': 'CSP header missing'
            }
            
            for header, description in security_checks.items():
                if header not in headers:
                    self.vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'service': 'web',
                        'vulnerability': f'Missing Security Header',
                        'severity': 'LOW',
                        'description': description
                    })
            
            server = headers.get('Server', '')
            if server:
                self.logger.info(f"Web sunucusu: {server}")
                
        except Exception as e:
            pass
    
    def check_ftp_anonymous(self, target, port):
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login()
            
            self.vulnerabilities.append({
                'target': target,
                'port': port,
                'service': 'ftp',
                'vulnerability': 'Anonymous FTP Access',
                'severity': 'MEDIUM',
                'description': 'Anonymous FTP login allowed'
            })
            self.logger.warning(f"FTP anonim giriş açığı: {target}:{port}")
            
            ftp.quit()
        except:
            pass

class PacketSniffer:
    
    def __init__(self, logger, interface=None):
        self.logger = logger
        self.interface = interface
        self.packet_count = 0
        self.protocol_stats = Counter()
        self.captured_packets = []
        self.is_sniffing = False
    
    def start_sniffing(self, packet_count=100, filter_str="", output_file=None):
        if not SCAPY_AVAILABLE:
            self.logger.error("Paket dinleme için scapy gerekli!")
            return
        
        self.logger.info(f"Paket dinleme başlatılıyor... (Interface: {self.interface})")
        self.is_sniffing = True
        
        def packet_handler(packet):
            if not self.is_sniffing:
                return
            
            self.packet_count += 1
            self.captured_packets.append(packet)
            
            if IP in packet:
                proto = packet[IP].proto
                if proto == 6:
                    self.protocol_stats['TCP'] += 1
                elif proto == 17:
                    self.protocol_stats['UDP'] += 1
                elif proto == 1:
                    self.protocol_stats['ICMP'] += 1
            
            self.log_packet(packet)
            
            if self.packet_count >= packet_count:
                self.is_sniffing = False
        
        try:
            sniff(iface=self.interface, prn=packet_handler, 
                  count=packet_count, filter=filter_str, store=False)
            
            self.generate_sniff_report(output_file)
            
        except Exception as e:
            self.logger.error(f"Paket dinleme hatası: {e}")
    
    def stop_sniffing(self):
        self.is_sniffing = False
    
    def log_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            packet_info = f"{src_ip} -> {dst_ip} "
            
            if TCP in packet:
                packet_info += f"TCP {packet[TCP].sport}->{packet[TCP].dport} "
                flags = packet[TCP].flags
                if flags & 0x02:
                    packet_info += "[SYN]"
                elif flags & 0x10:
                    packet_info += "[ACK]"
                elif flags & 0x04:
                    packet_info += "[RST]"
                elif flags & 0x01:
                    packet_info += "[FIN]"
            
            elif UDP in packet:
                packet_info += f"UDP {packet[UDP].sport}->{packet[UDP].dport}"
            
            elif ICMP in packet:
                packet_info += "ICMP"
            
            self.logger.info(f"[Paket {self.packet_count}] {packet_info}")
    
    def generate_sniff_report(self, output_file=None):
        self.logger.info("Paket dinleme tamamlandı!")
        self.logger.info(f"Toplam paket: {self.packet_count}")
        self.logger.info("Protokol istatistikleri:")
        
        for protocol, count in self.protocol_stats.items():
            self.logger.info(f"  {protocol}: {count}")
        
        if output_file:
            self.save_packets_to_file(output_file)
    
    def save_packets_to_file(self, filename):
        try:
            wrpcap(filename, self.captured_packets)
            self.logger.success(f"Paketler {filename} dosyasına kaydedildi")
        except Exception as e:
            self.logger.error(f"Paket kaydetme hatası: {e}")

class AdvancedNetworkScanner:
    
    def __init__(self, logger):
        self.logger = logger
        self.network_utils = NetworkUtils()
    
    def arp_scan(self, network):
        self.logger.info(f"ARP taraması başlatılıyor: {network}")
        
        if not SCAPY_AVAILABLE:
            self.logger.error("ARP taraması için scapy gerekli!")
            return []
        
        active_hosts = []
        
        try:
            ans, unans = arping(network, timeout=2, verbose=0)
            
            for sent, received in ans:
                active_hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self.get_mac_vendor(received.hwsrc)
                })
                self.logger.success(f"Bulundu: {received.psrc} - {received.hwsrc}")
                
        except Exception as e:
            self.logger.error(f"ARP taraması hatası: {e}")
        
        return active_hosts
    
    def get_mac_vendor(self, mac_address):
        mac_vendors = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:1D:0F': 'Dell',
            '00:21:5A': 'Dell',
            '00:25:64': 'Dell',
            '00:26:4A': 'Dell',
            '00:15:5D': 'Microsoft',
            '00:1B:21': 'Hewlett Packard',
            '00:1E:0B': 'Hewlett Packard',
            '00:23:7D': 'Hewlett Packard',
            '00:25:B3': 'Hewlett Packard',
            '00:1A:A0': 'Intel',
            '00:1B:21': 'Intel',
            '00:1C:C0': 'Intel',
            '00:1D:E1': 'Intel',
            '00:21:6A': 'Intel',
            '00:26:C7': 'Intel',
            '00:50:BA': 'IBM',
            '00:14:5E': 'IBM',
            '00:18:71': 'IBM',
            '00:21:5E': 'IBM',
            '00:11:85': 'Apple',
            '00:17:F2': 'Apple',
            '00:1C:B3': 'Apple',
            '00:1E:C2': 'Apple',
            '00:1F:5B': 'Apple',
            '00:1F:F3': 'Apple',
            '00:22:41': 'Apple',
            '00:23:12': 'Apple',
            '00:23:32': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:26:08': 'Apple',
            '00:26:4A': 'Apple',
            '00:26:B0': 'Apple',
            '00:30:65': 'Apple',
            '00:3E:E1': 'Apple',
            '00:4E:E1': 'Androit'
        }
        
        mac_prefix = mac_address.upper()[:8]
        return mac_vendors.get(mac_prefix, 'Bilinmiyor')
    
    def traceroute(self, target, max_hops=30):
        self.logger.info(f"Traceroute başlatılıyor: {target}")
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Traceroute için scapy gerekli!")
            return []
        
        route = []
        
        for ttl in range(1, max_hops + 1):
            pkt = IP(dst=target, ttl=ttl) / ICMP()
            try:
                reply = sr1(pkt, timeout=2, verbose=0)
                
                if reply is None:
                    route.append(f"{ttl}: * * *")
                    continue
                
                if reply.src == target:
                    route.append(f"{ttl}: {reply.src}")
                    break
                
                route.append(f"{ttl}: {reply.src}")
            except Exception as e:
                route.append(f"{ttl}: Hata - {str(e)}")
                continue
            
            if ttl >= max_hops:
                break
        
        return route
    
    def dns_enumeration(self, domain):
        self.logger.info(f"DNS enumeration başlatılıyor: {domain}")
        
        if not DNS_AVAILABLE:
            self.logger.error("DNS enumeration için dnspython kütüphanesi gerekli!")
            return {}
        
        records = {}
        
        try:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except:
                    records[record_type] = []
            
            subdomains = self.brute_force_subdomains(domain)
            records['SUBDOMAINS'] = subdomains
            
        except Exception as e:
            self.logger.error(f"DNS enumeration hatası: {e}")
        
        return records
    
    def brute_force_subdomains(self, domain, wordlist=None):
        if wordlist is None:
            wordlist = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'ssh']
        
        found_subdomains = []
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                found_subdomains.append(f"{full_domain} -> {ip}")
                self.logger.success(f"Subdomain bulundu: {full_domain} -> {ip}")
            except:
                pass
        
        return found_subdomains

class WebScanner:
    
    def __init__(self, logger):
        self.logger = logger
        self.vulnerabilities = []
    
    def scan_website(self, url):
        self.logger.info(f"Web sitesi taraması başlatılıyor: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        results = {
            'url': url,
            'headers': {},
            'technologies': [],
            'vulnerabilities': [],
            'directories': []
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            
            self.analyze_headers(response.headers, url, results)
            self.detect_technologies(response, results)
            self.check_common_vulnerabilities(url, results)
            self.directory_bruteforce(url, results)
            
        except Exception as e:
            self.logger.error(f"Web tarama hatası: {e}")
        
        return results
    
    def analyze_headers(self, headers, url, results):
        security_headers = {
            'X-Frame-Options': 'Clickjacking koruması',
            'X-Content-Type-Options': 'MIME sniffing koruması',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': 'XSS koruması',
            'Referrer-Policy': 'Referrer politikası'
        }
        
        missing_headers = []
        
        for header, description in security_headers.items():
            if header not in headers:
                missing_headers.append(description)
                results['vulnerabilities'].append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'LOW',
                    'description': f'Eksik güvenlik başlığı: {header} - {description}'
                })
        
        if missing_headers:
            self.logger.warning(f"Eksik güvenlik başlıkları: {', '.join(missing_headers)}")
    
    def detect_technologies(self, response, results):
        server = response.headers.get('Server', '')
        if server:
            results['technologies'].append(f"Sunucu: {server}")
        
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            results['technologies'].append(f"Framework: {powered_by}")
        
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            html_content = response.text.lower()
            
            tech_indicators = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'joomla': ['joomla', 'media/jui', 'templates/system'],
                'drupal': ['drupal', 'sites/all'],
                'laravel': ['laravel', 'csrf-token'],
                'react': ['react', 'react-dom'],
                'angular': ['angular', 'ng-'],
                'jquery': ['jquery'],
                'bootstrap': ['bootstrap']
            }
            
            for tech, indicators in tech_indicators.items():
                if any(indicator in html_content for indicator in indicators):
                    results['technologies'].append(tech)
    
    def check_common_vulnerabilities(self, url, results):
        test_paths = {
            '/admin': 'Admin panel erişimi',
            '/phpinfo.php': 'PHP info açığı',
            '/.git/': 'Git dizini açığı',
            '/backup/': 'Yedek dizini',
            '/wp-admin/': 'WordPress admin',
            '/phpMyAdmin/': 'phpMyAdmin erişimi'
        }
        
        for path, description in test_paths.items():
            try:
                test_url = url.rstrip('/') + path
                response = requests.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    results['vulnerabilities'].append({
                        'type': 'SENSITIVE_PATH_EXPOSED',
                        'severity': 'MEDIUM',
                        'description': f'Hassas yol açık: {path} - {description}'
                    })
                    self.logger.warning(f"Hassas yol bulundu: {test_url}")
            except:
                pass
    
    def directory_bruteforce(self, url, results, wordlist=None):
        if wordlist is None:
            wordlist = [
                'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
                'backup', 'backups', 'old', 'test', 'dev', 'development',
                'api', 'doc', 'docs', 'documentation', 'files', 'images',
                'img', 'js', 'css', 'uploads', 'download', 'downloads',
                'cgi-bin', 'server-status', 'config', 'configuration',
                'sql', 'database', 'db', 'archive', 'archives'
            ]
        
        found_directories = []
        
        for directory in wordlist:
            try:
                test_url = url.rstrip('/') + '/' + directory
                response = requests.get(test_url, timeout=3, verify=False)
                
                if response.status_code in [200, 301, 302]:
                    found_directories.append({
                        'path': directory,
                        'status': response.status_code,
                        'url': test_url
                    })
                    
                    if response.status_code == 200:
                        self.logger.info(f"Dizin bulundu: {test_url} (200)")
                    else:
                        self.logger.info(f"Yönlendirme: {test_url} ({response.status_code})")
                        
            except:
                pass
        
        results['directories'] = found_directories

class AdvancedPacketAnalyzer:
    
    def __init__(self, logger):
        self.logger = logger
        self.packet_stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'source_ips': Counter(),
            'destination_ips': Counter(),
            'ports': Counter(),
            'suspicious_activities': []
        }
    
    def analyze_pcap_file(self, pcap_file):
        if not SCAPY_AVAILABLE:
            self.logger.error("PCAP analizi için scapy gerekli!")
            return
        
        self.logger.info(f"PCAP dosyası analiz ediliyor: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            
            for packet in packets:
                self.analyze_packet(packet)
            
            self.generate_analysis_report()
            
        except Exception as e:
            self.logger.error(f"PCAP analiz hatası: {e}")
    
    def analyze_packet(self, packet):
        self.packet_stats['total_packets'] += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            self.packet_stats['source_ips'][src_ip] += 1
            self.packet_stats['destination_ips'][dst_ip] += 1
            
            proto = packet[IP].proto
            if proto == 6:
                self.packet_stats['protocols']['TCP'] += 1
                if TCP in packet:
                    self.packet_stats['ports'][packet[TCP].dport] += 1
                    self.check_tcp_suspicious(packet)
            elif proto == 17:
                self.packet_stats['protocols']['UDP'] += 1
                if UDP in packet:
                    self.packet_stats['ports'][packet[UDP].dport] += 1
            elif proto == 1:
                self.packet_stats['protocols']['ICMP'] += 1
                self.check_icmp_suspicious(packet)
        
        if ARP in packet:
            self.packet_stats['protocols']['ARP'] += 1
            self.check_arp_suspicious(packet)
    
    def check_tcp_suspicious(self, packet):
        if TCP in packet and IP in packet:
            flags = packet[TCP].flags
            
            if flags & 0x02 and not flags & 0x10:
                if packet[TCP].dport in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                    self.packet_stats['suspicious_activities'].append(
                        f"SYN flood şüphesi: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport}"
                    )
    
    def check_icmp_suspicious(self, packet):
        if ICMP in packet:
            if packet[ICMP].type == 8:
                if len(packet) > 1000:
                    self.packet_stats['suspicious_activities'].append(
                        f"Büyük ICMP paketi: {packet[IP].src} -> {packet[IP].dst}"
                    )
    
    def check_arp_suspicious(self, packet):
        if ARP in packet:
            if packet[ARP].op == 2:
                self.packet_stats['suspicious_activities'].append(
                    f"ARP spoofing şüphesi: {packet[ARP].hwsrc} -> {packet[ARP].psrc}"
                )
    
    def generate_analysis_report(self):
        self.logger.info("Paket analiz raporu:")
        self.logger.info(f"Toplam paket: {self.packet_stats['total_packets']}")
        
        self.logger.info("Protokol dağılımı:")
        for protocol, count in self.packet_stats['protocols'].items():
            percentage = (count / self.packet_stats['total_packets']) * 100
            self.logger.info(f"  {protocol}: {count} ({percentage:.2f}%)")
        
        self.logger.info("En aktif kaynak IP'ler:")
        for ip, count in self.packet_stats['source_ips'].most_common(5):
            self.logger.info(f"  {ip}: {count} paket")
        
        self.logger.info("En aktif hedef portlar:")
        for port, count in self.packet_stats['ports'].most_common(10):
            service = NetworkUtils.get_service_name(port)
            self.logger.info(f"  {port} ({service}): {count} paket")
        
        if self.packet_stats['suspicious_activities']:
            self.logger.warning("Şüpheli aktiviteler tespit edildi:")
            for activity in self.packet_stats['suspicious_activities'][:10]:
                self.logger.warning(f"  {activity}")

class NetworkDiscovery:
    
    def __init__(self, logger):
        self.logger = logger
    
    def get_network_range(self, ip):
        """Get the network range from an IP address"""
        try:
            # If it's already in CIDR format, return it
            if '/' in ip:
                return ip
            
            # Get network range based on IP class
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                # Class C network by default (24-bit mask)
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                return network
        except:
            return None
    
    def discover_network_hosts(self, network, timeout=1, max_threads=100):
        """Discover hosts in a network using ping sweep"""
        active_hosts = []
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            hosts = list(network_obj.hosts())
            
            # Limit to first 256 hosts to avoid overwhelming the network
            hosts = hosts[:256]
            
            def ping_host(host):
                try:
                    # Platform-independent ping
                    if sys.platform.startswith('win'):
                        result = subprocess.run(['ping', '-n', '1', '-w', str(int(timeout*1000)), str(host)], 
                                              capture_output=True, text=True)
                        success = result.returncode == 0
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', str(int(timeout)), str(host)], 
                                              capture_output=True, text=True)
                        success = result.returncode == 0
                    
                    if success:
                        return str(host)
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(ping_host, host) for host in hosts]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        active_hosts.append(result)
                        self.logger.success(f"Host aktif: {result}")
                        
        except Exception as e:
            self.logger.error(f"Ağ taraması hatası: {e}")
        
        return active_hosts
    
    def analyze_ip(self, target_ip):
        """Analyze an IP address and discover related IPs"""
        results = {
            'target_ip': target_ip,
            'network_range': None,
            'discovered_hosts': [],
            'gateway': None,
            'dns_info': {}
        }
        
        try:
            # Get network range
            network_range = self.get_network_range(target_ip)
            if network_range:
                results['network_range'] = network_range
                self.logger.info(f"Ağ aralığı belirlendi: {network_range}")
                
                # Discover hosts in the network
                hosts = self.discover_network_hosts(network_range)
                results['discovered_hosts'] = hosts
                self.logger.info(f"Toplam {len(hosts)} aktif host bulundu")
                
                # Try to determine gateway (usually .1 or .254 in the network)
                network_obj = ipaddress.IPv4Network(network_range, strict=False)
                gateway_ip1 = f"{network_obj.network_address}.1".replace('.0.1', '.1')
                gateway_ip2 = f"{network_obj.network_address}.254".replace('.0.254', '.254')
                
                for host in [gateway_ip1, gateway_ip2]:
                    try:
                        host_ip = str(host)
                        if host_ip in hosts:
                            results['gateway'] = host_ip
                            self.logger.info(f"Ağ geçidi tahmini: {host_ip}")
                            break
                    except:
                        continue
            
            # Get DNS information
            try:
                dns_info = socket.gethostbyaddr(target_ip)
                results['dns_info'] = {
                    'hostname': dns_info[0],
                    'aliases': dns_info[1],
                    'addresses': dns_info[2]
                }
                self.logger.info(f"DNS bilgisi: {dns_info[0]}")
            except socket.herror:
                # No reverse DNS entry
                pass
            except:
                # Other errors
                pass
                
        except Exception as e:
            self.logger.error(f"IP analiz hatası: {e}")
        
        return results

class ProxyScanner:
    
    def __init__(self, logger):
        self.logger = logger
    
    def check_proxy(self, host, port, timeout=5):
        """Check if a host:port combination works as a proxy"""
        try:
            # Simple connection test to see if it accepts proxy connections
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # If connection is successful, try to determine if it's a proxy
                # Basic proxy identification by trying to send a simple proxy request
                try:
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(timeout)
                    test_sock.connect((host, port))
                    
                    # Try sending a basic HTTP CONNECT request
                    http_request = f"CONNECT www.google.com:80 HTTP/1.0\r\n\r\n"
                    test_sock.send(http_request.encode())
                    
                    response = test_sock.recv(1024).decode('utf-8', errors='ignore')
                    test_sock.close()
                    
                    # If we get a response that looks like proxy response
                    if '200' in response or 'proxy' in response.lower() or 'connect' in response.lower():
                        self.logger.success(f"Proxy bulundu: {host}:{port}")
                        return f"HTTP Proxy: {host}:{port}"
                    else:
                        # If connection works but not a proxy, it might be an open port
                        return f"Open Port: {host}:{port}"
                except:
                    # If it connects but doesn't respond like a proxy, it might just be an open port
                    return f"Open Port: {host}:{port}"
            else:
                return None
        except Exception as e:
            return None
    
    def scan_for_proxies(self, host, ports):
        """Scan a host for proxy services on given ports"""
        proxies = []
        
        for port in ports:
            proxy_info = self.check_proxy(host, port)
            if proxy_info:
                proxies.append((port, proxy_info))
                
        return proxies

class WirelessScanner:
    
    def __init__(self, logger):
        self.logger = logger
        self.wireless_networks = []
    
    def scan_wireless_networks(self, interface="wlan0"):
        self.logger.info(f"Kablosuz ağ taraması başlatılıyor: {interface}")
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Kablosuz tarama için scapy gerekli!")
            return []
        
        # Check if Dot11 layers are available
        try:
            from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
        except ImportError:
            self.logger.error("Dot11 katmanları scapy'de mevcut değil!")
            return []
        
        try:
            networks = []
            
            def packet_handler(packet):
                if packet.haslayer(Dot11Beacon):
                    # Safely extract SSID
                    ssid = ""
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except:
                        ssid = "<unknown>"
                    
                    bssid = packet[Dot11].addr2
                    
                    # Safely extract channel
                    channel = 0
                    try:
                        channel = int(ord(packet[Dot11Elt:3].info))
                    except:
                        channel = 0
                    
                    signal_strength = getattr(packet, 'dBm_AntSignal', -100)
                    
                    crypto = "OPEN"
                    try:
                        # More robust crypto detection
                        elt_layer = packet.getlayer(Dot11Elt)
                        while elt_layer:
                            if elt_layer.ID == 48:  # RSN IE
                                crypto = "WPA2"
                                break
                            elif elt_layer.ID == 221 and b"WPA" in elt_layer.info:
                                crypto = "WPA"
                                break
                            elt_layer = elt_layer.payload.getlayer(Dot11Elt)
                    except:
                        pass
                    
                    network_info = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'channel': channel,
                        'signal': signal_strength,
                        'encryption': crypto
                    }
                    
                    # Check for duplicates more safely
                    is_duplicate = False
                    for existing_net in networks:
                        if existing_net['bssid'] == bssid:
                            is_duplicate = True
                            break
                    
                    if not is_duplicate:
                        networks.append(network_info)
                        self.logger.info(f"WiFi Ağı: {ssid} - {bssid} - Kanal: {channel} - Şifreleme: {crypto}")
            
            sniff(iface=interface, prn=packet_handler, timeout=10)
            
            self.wireless_networks = networks
            return networks
            
        except Exception as e:
            self.logger.error(f"Kablosuz tarama hatası: {e}")
            return []

class qntscanner:
    
    def __init__(self):
        self.logger = Logger()
        self.network_utils = NetworkUtils()
        self.port_scanner = PortScanner(self.logger)
        self.vuln_scanner = VulnerabilityScanner(self.logger)
        self.packet_sniffer = PacketSniffer(self.logger)
        self.advanced_scanner = AdvancedNetworkScanner(self.logger)
        self.web_scanner = WebScanner(self.logger)
        self.packet_analyzer = AdvancedPacketAnalyzer(self.logger)
        self.wireless_scanner = WirelessScanner(self.logger)
        self.network_discovery = NetworkDiscovery(self.logger)
        
        self.scan_results = {}
        self.host_info = {}
        self.network_info = {}
    
    def comprehensive_scan(self, target, ports="1-1000", scan_type="tcp"):
        self.logger.info(f"Kapsamlı tarama başlatılıyor: {target}")
        
        start_time = time.time()
        
        self.gather_host_info(target)
        
        # If target is an IP address, analyze the network
        if self.is_valid_ip(target):
            self.logger.info(f"IP analizi başlatılıyor: {target}")
            self.network_info = self.network_discovery.analyze_ip(target)
        
        port_list = self.parse_port_range(ports)
        
        if scan_type == "tcp":
            self.scan_results = self.port_scanner.tcp_connect_scan(target, port_list)
        elif scan_type == "syn":
            self.scan_results = self.port_scanner.syn_scan(target, port_list)
        elif scan_type == "udp":
            self.scan_results = self.port_scanner.udp_scan(target, port_list)
        elif scan_type == "all":
            self.scan_results = self.port_scanner.tcp_connect_scan(target, port_list)
            udp_results = self.port_scanner.udp_scan(target, port_list)
            self.scan_results.update(udp_results)
        
        for port, info in self.scan_results.items():
            if info['status'] == 'open':
                self.vuln_scanner.scan_common_vulnerabilities(target, port, info['service'])
        
        end_time = time.time()
        
        self.generate_report(target, end_time - start_time)
        
        return self.scan_results
    
    def gather_host_info(self, target):
        self.logger.info(f"Hedef bilgileri toplanıyor: {target}")
        
        self.host_info['target'] = target
        self.host_info['scan_time'] = datetime.now().isoformat()
        
        try:
            dns_info = socket.gethostbyaddr(target)
            self.host_info['hostname'] = dns_info[0]
            self.host_info['aliases'] = dns_info[1]
            self.host_info['ip_addresses'] = dns_info[2]
        except:
            self.host_info['hostname'] = target
        
        try:
            ttl = self.get_ttl(target)
            self.host_info['ttl'] = ttl
            if ttl <= 64:
                self.host_info['os_guess'] = 'Linux/Unix'
            elif ttl <= 128:
                self.host_info['os_guess'] = 'Windows'
            else:
                self.host_info['os_guess'] = 'Other'
        except:
            pass
    
    def get_ttl(self, target):
        try:
            pkt = IP(dst=target)/ICMP()
            reply = sr1(pkt, timeout=2, verbose=0)
            if reply:
                return reply[IP].ttl
        except:
            pass
        return 0
    
    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def parse_port_range(self, port_range):
        ports = []
        
        if "," in port_range:
            parts = port_range.split(",")
            for part in parts:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
        elif "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = list(range(start, end + 1))
        else:
            ports = [int(port_range)]
        
        return ports
    
    def generate_report(self, target, duration):
        self.logger.info("Tarama raporu oluşturuluyor...")
        
        report = {
            'scan_info': self.host_info,
            'scan_results': self.scan_results,
            'vulnerabilities': self.vuln_scanner.vulnerabilities,
            'network_info': getattr(self, 'network_info', {}),
            'statistics': {
                'total_ports_scanned': len(self.scan_results),
                'open_ports': len([p for p, info in self.scan_results.items() 
                                 if info.get('status') == 'open']),
                'scan_duration': f"{duration:.2f} seconds",
                'vulnerabilities_found': len(self.vuln_scanner.vulnerabilities)
            }
        }
        
        self.print_report(report)
        
        self.save_report(report, f"qnt_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        return report
    
    def print_report(self, report):
        print("\n" + "="*60)
        print("QNTSOFT TARAMA RAPORU")
        print("="*60)
        
        print(f"\nHedef: {report['scan_info']['target']}")
        print(f"Tarama Zamani: {report['scan_info']['scan_time']}")
        if 'hostname' in report['scan_info']:
            print(f"Hostname: {report['scan_info']['hostname']}")
        if 'os_guess' in report['scan_info']:
            print(f"OS Tahmini: {report['scan_info']['os_guess']}")
        
        print(f"\nIstatistikler:")
        print(f"  Taranan Port: {report['statistics']['total_ports_scanned']}")
        print(f"  Acik Port: {report['statistics']['open_ports']}")
        print(f"  Sure: {report['statistics']['scan_duration']}")
        print(f"  Tespit Edilen Guvenlik Aciklari: {report['statistics']['vulnerabilities_found']}")
        
        # Print network discovery information if available
        if report.get('network_info') and report['network_info'].get('discovered_hosts'):
            print(f"\nAĞ ANALİZİ:")
            network_info = report['network_info']
            if network_info.get('network_range'):
                print(f"  Ağ Aralığı: {network_info['network_range']}")
            if network_info.get('gateway'):
                print(f"  Ağ Geçidi: {network_info['gateway']}")
            print(f"  Keşfedilen Hostlar: {len(network_info['discovered_hosts'])}")
            for host in network_info['discovered_hosts'][:10]:  # Show first 10 hosts
                print(f"    - {host}")
            if len(network_info['discovered_hosts']) > 10:
                print(f"    ... ve {len(network_info['discovered_hosts']) - 10} tane daha")
        
        if report['statistics']['open_ports'] > 0:
            print(f"\nACIK PORTLAR:")
            print("Port\tProtokol\tServis\t\tBanner")
            print("-" * 60)
            for port, info in report['scan_results'].items():
                if info.get('status') == 'open':
                    banner = info.get('banner', '')
                    banner_display = banner[:30] + "..." if len(banner) > 30 else banner
                    protocol = info.get('protocol', 'unknown')
                    service = info.get('service', 'unknown')
                    print(f"{port}\t{protocol}\t\t{service}\t\t{banner_display}")
        
        if report['vulnerabilities']:
            print(f"\nGUVENLIK ACIKLARI:")
            for vuln in report['vulnerabilities']:
                print(f"  [{vuln['severity']}] {vuln['vulnerability']} - {vuln['description']}")
        
        print("\n" + "="*60)
    
    def save_report(self, report, filename):
        try:
            txt_filename = filename.replace('.json', '.txt').replace('CONST', 'QNT')
            with open(txt_filename, 'w', encoding='utf-8') as f:
                self.save_report_txt(report, f)
            self.logger.success(f"Rapor {txt_filename} dosyasına kaydedildi")
        except Exception as e:
            self.logger.error(f"Rapor kaydetme hatası: {e}")
    
    def save_report_txt(self, report, file_handle):
        file_handle.write("QNTSOFTWARE TARAMA RAPORU\n")
        file_handle.write("=" * 60 + "\n\n")
        
        file_handle.write(f"Hedef: {report['scan_info']['target']}\n")
        file_handle.write(f"Tarama Zamani: {report['scan_info']['scan_time']}\n")
        if 'hostname' in report['scan_info']:
            file_handle.write(f"Hostname: {report['scan_info']['hostname']}\n")
        if 'os_guess' in report['scan_info']:
            file_handle.write(f"OS Tahmini: {report['scan_info']['os_guess']}\n\n")
        
        file_handle.write("Istatistikler:\n")
        file_handle.write(f"  Taranan Port: {report['statistics']['total_ports_scanned']}\n")
        file_handle.write(f"  Acik Port: {report['statistics']['open_ports']}\n")
        file_handle.write(f"  Sure: {report['statistics']['scan_duration']}\n")
        file_handle.write(f"  Tespit Edilen Guvenlik Aciklari: {report['statistics']['vulnerabilities_found']}\n\n")
        
        # Write network discovery information if available
        if report.get('network_info') and report['network_info'].get('discovered_hosts'):
            file_handle.write("AĞ ANALİZİ:\n")
            network_info = report['network_info']
            if network_info.get('network_range'):
                file_handle.write(f"  Ağ Aralığı: {network_info['network_range']}\n")
            if network_info.get('gateway'):
                file_handle.write(f"  Ağ Geçidi: {network_info['gateway']}\n")
            file_handle.write(f"  Keşfedilen Hostlar: {len(network_info['discovered_hosts'])}\n")
            for host in network_info['discovered_hosts'][:10]:  # Show first 10 hosts
                file_handle.write(f"    - {host}\n")
            if len(network_info['discovered_hosts']) > 10:
                file_handle.write(f"    ... ve {len(network_info['discovered_hosts']) - 10} tane daha\n")
            file_handle.write("\n")
        
        if report['statistics']['open_ports'] > 0:
            file_handle.write("ACIK PORTLAR:\n")
            file_handle.write("Port\tProtokol\tServis\t\tBanner\t\tProxy\n")
            file_handle.write("-" * 80 + "\n")
            for port, info in report['scan_results'].items():
                if info.get('status') == 'open':
                    banner = info.get('banner', '')
                    banner_display = banner[:30] + "..." if len(banner) > 30 else banner
                    protocol = info.get('protocol', 'unknown')
                    service = info.get('service', 'unknown')
                    # Proxy information will be added later
                    proxy_info = info.get('proxy', 'Yok')
                    file_handle.write(f"{port}\t{protocol}\t\t{service}\t\t{banner_display}\t\t{proxy_info}\n")
        
        if report['vulnerabilities']:
            file_handle.write("\nGUVENLIK ACIKLARI:\n")
            for vuln in report['vulnerabilities']:
                file_handle.write(f"  [{vuln['severity']}] {vuln['vulnerability']} - {vuln['description']}\n")
        
        file_handle.write("\n" + "="*60 + "\n")
    
    def advanced_scan(self, target, options):
        self.logger.info("Gelişmiş tarama başlatılıyor...")
        
        results = {
            'basic_scan': {},
            'network_scan': {},
            'web_scan': {},
            'wireless_scan': {},
            'packet_analysis': {}
        }
        
        if options.get('basic_scan', True):
            results['basic_scan'] = self.comprehensive_scan(target, options.get('ports', '1-1000'))
        
        if options.get('network_scan', False):
            if '/' in target:
                results['network_scan']['arp'] = self.advanced_scanner.arp_scan(target)
            results['network_scan']['traceroute'] = self.advanced_scanner.traceroute(target)
            results['network_scan']['dns'] = self.advanced_scanner.dns_enumeration(target)
        
        if options.get('web_scan', False):
            results['web_scan'] = self.web_scanner.scan_website(target)
        
        if options.get('wireless_scan', False):
            results['wireless_scan'] = self.wireless_scanner.scan_wireless_networks()
        
        if options.get('packet_analysis', False) and options.get('pcap_file'):
            self.packet_analyzer.analyze_pcap_file(options['pcap_file'])
        
        self.generate_advanced_report(results)
        return results
    
    def generate_advanced_report(self, results):
        self.logger.info("GELİŞMİŞ TARAMA RAPORU")
        self.logger.info("=" * 50)
        
        if results['basic_scan']:
            open_ports = len([p for p, info in results['basic_scan'].items() if info['status'] == 'open'])
            self.logger.info(f"Açık portlar: {open_ports}")
        
        if results['network_scan']:
            if 'arp' in results['network_scan']:
                self.logger.info(f"Bulunan hostlar: {len(results['network_scan']['arp'])}")
            if 'dns' in results['network_scan']:
                self.logger.info(f"DNS kayıtları: {len(results['network_scan']['dns'])}")
        
        if results['web_scan']:
            vulns = len(results['web_scan'].get('vulnerabilities', []))
            self.logger.info(f"Web güvenlik açıkları: {vulns}")
        
        if results['wireless_scan']:
            self.logger.info(f"Kablosuz ağlar: {len(results['wireless_scan'])}")

def main():
    parser = argparse.ArgumentParser(
        description="QNT PORT SCANNER - Gelişmiş Ağ Analiz ve Güvenlik Tarama Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnek Kullanımlar:
  python qntport.py 192.168.1.1
  python qntport.py 192.168.1.1 -p 1-1000 -t syn
  python qntport.py 192.168.1.0/24 --ping
  python qntport.py --sniff -i eth0 -c 100
  python qntport.py example.com -p 80,443,22 --vuln-scan
  python qntport.py --advanced 192.168.1.1
  python qntport.py --network-scan 192.168.1.0/24
  python qntport.py --web-scan example.com
  python qntport.py --wireless-scan
  python qntport.py --packet-analysis capture.pcap
        """
    )
    
    parser.add_argument("target", nargs="?", help="Hedef IP, hostname veya ağ")
    parser.add_argument("-p", "--ports", default="1-1000", help="Taranacak port aralığı")
    parser.add_argument("-t", "--scan-type", choices=["tcp", "syn", "udp", "all"], default="tcp", help="Tarama tipi")
    parser.add_argument("--threads", type=int, default=200, help="Thread sayısı")
    parser.add_argument("--timeout", type=float, default=1, help="Zaman aşımı")
    
    parser.add_argument("--ping", action="store_true", help="Ping taraması yap")
    parser.add_argument("--sniff", action="store_true", help="Paket dinleme modu")
    parser.add_argument("-i", "--interface", help="Ağ arayüzü")
    parser.add_argument("-c", "--count", type=int, default=100, help="Dinlenecek paket sayısı")
    parser.add_argument("-f", "--filter", default="", help="Paket filtreleme")
    
    parser.add_argument("--vuln-scan", action="store_true", help="Güvenlik açığı taraması yap")
    
    parser.add_argument("-o", "--output", help="Çıktı dosyası")
    parser.add_argument("--json", action="store_true", help="JSON formatında çıktı")
    parser.add_argument("--csv", action="store_true", help="CSV formatında çıktı")
    
    parser.add_argument("--advanced", action="store_true", help="Gelişmiş tarama")
    parser.add_argument("--network-scan", action="store_true", help="Ağ taraması")
    parser.add_argument("--web-scan", action="store_true", help="Web taraması")
    parser.add_argument("--wireless-scan", action="store_true", help="Kablosuz tarama")
    parser.add_argument("--packet-analysis", action="store_true", help="Paket analizi")
    parser.add_argument("--pcap-file", help="PCAP dosyası analizi")
    
    args = parser.parse_args()
    
    print(r"""
         .-')         .-') _  .-') _    
   .(  OO)       ( OO ) )(  OO) )   
  (_)---\_)  ,--./ ,--,' /     '._  
  '  .-.  '  |   \ |  |\ |'--...__) 
 ,|  | |  |  |    \|  | )'--.  .--' 
(_|  | |  |  |  .     |/    |  |    
  |  | |  |  |  |\    |     |  |    
  '  '-'  '-.|  | \   |     |  |    
   `-----'--'`--'  `--'     `--'    
    ====================================
        MADE BY: QNT SOFTWARE
        PROJECT: QNT PORT SCANNER
    ====================================
    """)
    
    scanner = qntscanner()
    
    if args.sniff:
        scanner.packet_sniffer.interface = args.interface
        scanner.packet_sniffer.start_sniffing(args.count, args.filter, args.output)
        return
    
    if not args.target and not args.wireless_scan:
        parser.print_help()
        return
    
    if args.ping and args.target:
        scanner.logger.info(f"Ping taraması: {args.target}")
        try:
            if "/" in args.target:
                network = ipaddress.ip_network(args.target, strict=False)
                for ip in list(network.hosts())[:10]:
                    # Platform-independent ping command
                    if sys.platform.startswith('win'):
                        response = os.system(f"ping -n 1 -w 1000 {ip} > nul 2>&1")
                    else:
                        response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
                    if response == 0:
                        scanner.logger.success(f"{ip} aktif")
            else:
                # Platform-independent ping command
                if sys.platform.startswith('win'):
                    response = os.system(f"ping -n 1 -w 1000 {args.target} > nul 2>&1")
                else:
                    response = os.system(f"ping -c 1 -W 1 {args.target} > /dev/null 2>&1")
                if response == 0:
                    scanner.logger.success(f"{args.target} aktif")
                else:
                    scanner.logger.error(f"{args.target} ulaşılamıyor")
        except Exception as e:
            scanner.logger.error(f"Ping taraması hatası: {e}")
        return
    
    if args.advanced and args.target:
        options = {
            'basic_scan': True,
            'network_scan': True,
            'web_scan': True,
            'wireless_scan': args.wireless_scan,
            'packet_analysis': args.packet_analysis,
            'pcap_file': args.pcap_file,
            'ports': '1-65535'
        }
        
        scanner.advanced_scan(args.target, options)
    
    elif args.network_scan and args.target:
        if '/' in args.target:
            results = scanner.advanced_scanner.arp_scan(args.target)
            scanner.logger.info(f"ARP tarama sonucu: {len(results)} host bulundu")
        else:
            scanner.logger.error("Ağ taraması için CIDR notasyonu gerekli (örn: 192.168.1.0/24)")
    
    elif args.web_scan and args.target:
        results = scanner.web_scanner.scan_website(args.target)
        scanner.logger.info(f"Web tarama tamamlandı: {len(results.get('vulnerabilities', []))} açık bulundu")
    
    elif args.wireless_scan:
        results = scanner.wireless_scanner.scan_wireless_networks()
        scanner.logger.info(f"Kablosuz tarama tamamlandı: {len(results)} ağ bulundu")
    
    elif args.packet_analysis and args.pcap_file:
        scanner.packet_analyzer.analyze_pcap_file(args.pcap_file)
    
    elif args.target:
        try:
            results = scanner.comprehensive_scan(args.target, args.ports, args.scan_type)
            
            if args.json and args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                scanner.logger.success(f"JSON çıktı {args.output} dosyasına kaydedildi")
            
            elif args.csv and args.output:
                with open(args.output, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Port', 'Status', 'Service', 'Protocol', 'Banner'])
                    for port, info in results.items():
                        writer.writerow([port, info['status'], info['service'], 
                                       info['protocol'], info['banner']])
                scanner.logger.success(f"CSV çıktı {args.output} dosyasına kaydedildi")
                
        except KeyboardInterrupt:
            scanner.logger.info("Kullanıcı tarafından durduruldu")
        except Exception as e:
            scanner.logger.error(f"Tarama hatası: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("Uyarı: Scapy kütüphanesi kurulu değil. Bazı özellikler kullanılamayacak.")
        print("Kurmak için: pip install scapy")
    
    if not PARAMIKO_AVAILABLE:
        print("Uyarı: Paramiko kütüphanesi kurulu değil. SSH tarama özellikleri kullanılamayacak.")
        print("Kurmak için: pip install paramiko")
    

    main()
