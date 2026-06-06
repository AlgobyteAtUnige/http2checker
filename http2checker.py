#!/usr/bin/env python3
#
#################################################
#
# HTTP2Checker
#
# Michele <o-zone@zerozone.it> Pinassi
#
# This script check an URL for DNS, HTTP/HTTPS presence, HTTP/2.0 support, SSL and HTTP server...
#
# v0.1 - 06.06.2026 - First release
#
#################################################

import socket
import ipaddress
import ssl
import os
import argparse
import http.client
import re
import html
import urllib.parse
import csv
from typing import List, Dict, Any

def parse_issuer(cert: Any) -> str:
    if not cert: return "N/A"
    fallback_ca = "Unknown CA"
    for item in cert.get('issuer', []):
        for subitem in item:
            if subitem[0] == 'commonName':
                return subitem[1]
            elif subitem[0] == 'organizationName':
                fallback_ca = subitem[1]
    return fallback_ca

def parse_expiry(cert: Any) -> str:
    if not cert or 'notAfter' not in cert: return "N/A"
    months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
              "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
    parts = cert['notAfter'].split()
    if len(parts) >= 4:
        month = months.get(parts[0], "00")
        day = parts[1].zfill(2)
        year = parts[3]
        return f"{year}-{month}-{day}"
    return cert['notAfter']

def estrai_titolo(html_content: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if match:
        titolo = match.group(1).strip()
        titolo = re.sub(r'\s+', ' ', titolo)
        return html.unescape(titolo)
    return "N/A"

def recupera_titolo_con_redirect(start_url: str, ignorare_ssl: bool, max_redirects: int = 4) -> str:
    url = start_url
    contesto_ssl = ssl._create_unverified_context() if ignorare_ssl else ssl.create_default_context()
    
    for _ in range(max_redirects):
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        scheme = parsed.scheme
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
            
        port = parsed.port if parsed.port else (443 if scheme == 'https' else 80)
        
        try:
            if scheme == 'https':
                conn = http.client.HTTPSConnection(host, port, timeout=5, context=contesto_ssl)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=5)
                
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Connection": "close"
            }
            conn.request("GET", path, headers=headers)
            res = conn.getresponse()
            
            if res.status in (301, 302, 303, 307, 308):
                location = res.getheader('Location')
                if location:
                    url = urllib.parse.urljoin(url, location)
                    conn.close()
                    continue
                else:
                    conn.close()
                    break
                    
            if res.status == 200:
                corpo_html = res.read(16384).decode('utf-8', errors='ignore')
                titolo = estrai_titolo(corpo_html)
                conn.close()
                return titolo
                
            conn.close()
            break
            
        except Exception:
            try: 
                conn.close() 
            except Exception: 
                pass
            break
            
    return "N/A"

def analizza_dominio(dominio: str, ignorare_ssl: bool = False) -> Dict[str, Any]:
    risultato = {
        "dominio": dominio,
        "dns_risolve": False,
        "ip": None,
        "ip_pubblico": False,
        "http_supportato": False,
        "https_supportato": False,
        "http2_supportato": False,
        "server_version": "N/A",
        "ssl_status": "N/A",
        "ssl_issuer": "N/A",
        "ssl_scadenza": "N/A",
        "titolo": "N/A"
    }

    try:
        ip = socket.gethostbyname(dominio)
        risultato["dns_risolve"] = True
        risultato["ip"] = ip
    except socket.gaierror:
        return risultato

    try:
        ip_obj = ipaddress.ip_address(ip)
        risultato["ip_pubblico"] = ip_obj.is_global
    except ValueError:
        pass

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Connection": "close"
    }

    # 1. Verifica HTTP
    try:
        conn = http.client.HTTPConnection(dominio, timeout=5)
        conn.request("HEAD", "/", headers=headers)
        res = conn.getresponse()
        risultato["http_supportato"] = True
        server_header = res.getheader('Server')
        if server_header:
            risultato["server_version"] = server_header
    except Exception:
        risultato["http_supportato"] = False
    finally:
        try: 
            conn.close() 
        except Exception: 
            pass

    # 2. Verifica HTTPS
    try:
        contesto_ssl = ssl._create_unverified_context() if ignorare_ssl else ssl.create_default_context()
        contesto_ssl.set_alpn_protocols(['h2', 'http/1.1'])
        
        conn = http.client.HTTPSConnection(dominio, timeout=5, context=contesto_ssl)
        conn.connect()
        risultato["https_supportato"] = True
        
        if conn.sock:
            risultato["http2_supportato"] = (conn.sock.selected_alpn_protocol() == 'h2')
            
            if not ignorare_ssl:
                risultato["ssl_status"] = "VALIDO"
                cert = conn.sock.getpeercert()
                if cert:
                    risultato["ssl_issuer"] = parse_issuer(cert)
                    risultato["ssl_scadenza"] = parse_expiry(cert)
            else:
                risultato["ssl_status"] = "BYPASS (-k)"
                risultato["ssl_issuer"] = "(Nascosto)"
                risultato["ssl_scadenza"] = "(Nascosto)"
        
        conn.request("HEAD", "/", headers=headers)
        res = conn.getresponse()
        server_header = res.getheader('Server')
        if server_header and risultato["server_version"] == "N/A":
            risultato["server_version"] = server_header
            
    except ssl.SSLError as e:
        risultato["https_supportato"] = True 
        err_str = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in err_str:
            if "expired" in err_str.lower():
                risultato["ssl_status"] = "SCADUTO"
            elif "self signed" in err_str.lower():
                risultato["ssl_status"] = "SELF-SIGNED"
            else:
                risultato["ssl_status"] = "ERR_CERT"
        elif "hostname doesn't match" in err_str.lower():
            risultato["ssl_status"] = "ERR_HOSTNAME"
        elif "wrong version number" in err_str.lower():
            risultato["ssl_status"] = "ERR_TLS_VERS"
        else:
            risultato["ssl_status"] = "ERR_SSL"
    except TimeoutError:
        risultato["ssl_status"] = "TIMEOUT"
    except ConnectionRefusedError:
        risultato["https_supportato"] = False
        risultato["ssl_status"] = "RIFIUTATA"
    except OSError:
        risultato["https_supportato"] = False
        risultato["ssl_status"] = "NO_HTTPS"
    except Exception as e:
        risultato["https_supportato"] = False
        risultato["ssl_status"] = f"E:{type(e).__name__}"[:11]
    finally:
        try: 
            conn.close() 
        except Exception: 
            pass

    # 3. Estrazione Titolo con Follow Redirect
    if risultato["http_supportato"] or risultato["https_supportato"]:
        start_scheme = "https" if risultato["https_supportato"] else "http"
        start_url = f"{start_scheme}://{dominio}/"
        risultato["titolo"] = recupera_titolo_con_redirect(start_url, ignorare_ssl)

    return risultato

def carica_domini_da_file(nome_file: str) -> List[str]:
    if not os.path.exists(nome_file):
        print(f"Errore: Il file '{nome_file}' non esiste.")
        return []
    domini = []
    with open(nome_file, "r", encoding="utf-8") as file:
        for riga in file:
            dominio_pulito = riga.strip()
            if dominio_pulito and not dominio_pulito.startswith("#"):
                domini.append(dominio_pulito)
    return domini

def main():
    parser = argparse.ArgumentParser(description="HTTP2Checker: DNS, IP, SSL, Server, Title and CSV export")
    parser.add_argument("dominio", nargs="?", help="A single URL to check")
    parser.add_argument("-f", "--file", help="List of URLs to check, one per line")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignore SSL error")
    parser.add_argument("-o", "--output", help="Export on CSV")
    
    args = parser.parse_args()
    if not args.dominio and not args.file:
        parser.print_help()
        return

    lista_domini = [args.dominio] if args.dominio else carica_domini_da_file(args.file)
    if not lista_domini: return

    # Configurazione scrittura CSV
    csv_file = None
    csv_writer = None
    if args.output:
        try:
            csv_file = open(args.output, mode='w', newline='', encoding='utf-8')
            csv_writer = csv.writer(csv_file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            # Scrittura Intestazione CSV
            csv_writer.writerow([
                "Dominio", "DNS", "IP", "Pubblico", "HTTP", "HTTPS", 
                "HTTP/2", "Server", "SSL Status", "Emittente", "Scadenza", "Titolo"
            ])
            print(f"I risultati verranno esportati in: {args.output}")
        except Exception as e:
            print(f"Errore nell'apertura del file CSV: {e}")
            return

    print("\nAvvio analisi...\n")
    print(f"{'DOMINIO':<22} | {'IP':<15} | {'HTTP':<4} | {'HTTPS':<5} | {'H2':<3} | {'SERVER':<10} | {'SSL STATUS':<11} | {'EMITTENTE':<12} | {'SCADENZA':<10} | {'TITOLO':<22}")
    print("-" * 133)

    for dom in lista_domini:
        res = analizza_dominio(dom, ignorare_ssl=args.insecure)
        
        # Preparazione variabili per logica N/A in caso di DNS fallito
        dns_status = "OK" if res["dns_risolve"] else "FAIL"
        ip_str = res["ip"] if res["ip"] else "N/A"
        pub_status = "SI" if res["ip_pubblico"] else "NO"
        http_status = "SI" if res["http_supportato"] else "NO"
        https_status = "SI" if res["https_supportato"] else "NO"
        h2_status = "SI" if res["http2_supportato"] else "NO"
        server_str = res["server_version"]
        ssl_str = res["ssl_status"]
        issuer_str = res["ssl_issuer"]
        expiry_str = res["ssl_scadenza"]
        titolo_str = res["titolo"]

        if not res["dns_risolve"]:
            pub_status = "N/A"
            http_status = "N/A"
            https_status = "N/A"
            h2_status = "N/A"
            server_str = "N/A"
            ssl_str = "N/A"
            issuer_str = "N/A"
            expiry_str = "N/A"
            titolo_str = "N/A"

        # Scrittura nel CSV (dati intatti, senza troncamenti)
        if csv_writer:
            csv_writer.writerow([
                res["dominio"], dns_status, ip_str, pub_status,
                http_status, https_status, h2_status, server_str,
                ssl_str, issuer_str, expiry_str, titolo_str
            ])
            # Forziamo la scrittura su disco ad ogni riga
            csv_file.flush()

        # Troncamento delle variabili SOLO per l'output a schermo
        dom_print = dom if len(dom) <= 22 else dom[:19] + "..."
        server_print = server_str if len(server_str) <= 10 else server_str[:7] + "..."
        ssl_print = ssl_str if len(ssl_str) <= 11 else ssl_str[:11]
        issuer_print = issuer_str if len(issuer_str) <= 12 else issuer_str[:9] + "..."
        titolo_print = titolo_str if len(titolo_str) <= 22 else titolo_str[:19] + "..."

        print(f"{dom_print:<22} | {ip_str:<15} | {http_status:<4} | {https_status:<5} | {h2_status:<3} | {server_print:<10} | {ssl_print:<11} | {issuer_print:<12} | {expiry_str:<10} | {titolo_print:<22}")

    if csv_file:
        csv_file.close()
        print(f"\nEsportazione completata. Dati salvati in: {args.output}")

if __name__ == "__main__":
    main()