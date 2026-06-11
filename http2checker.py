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
# v0.3 - 11.06.2026 - Fixed a bug in exception raised on invalid SSL cert. Added a comfortable summary at the end of the analysis.
# v0.2 - 06.06.2026 - A new PR merged with HTTP2 fixes, translated all to english
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
import traceback
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

def extract_title(html_content: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        title = re.sub(r'\s+', ' ', title)
        return html.unescape(title)
    return "N/A"

def get_title_with_redirect(start_url: str, ignore_ssl: bool, max_redirects: int = 4, verbose: bool = False) -> str:
    url = start_url
    ssl_context = ssl._create_unverified_context() if ignore_ssl else ssl.create_default_context()
    
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
                conn = http.client.HTTPSConnection(host, port, timeout=5, context=ssl_context)
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
                html_body = res.read(16384).decode('utf-8', errors='ignore')
                title = extract_title(html_body)
                conn.close()
                return title
                
            conn.close()
            break
            
        except Exception:
            if verbose:
                traceback.print_exc()
            try: 
                conn.close() 
            except Exception: 
                pass
            break
            
    return "N/A"

def analyze_domain(domain: str, ignore_ssl: bool = False, verbose: bool = False) -> Dict[str, Any]:
    result = {
        "domain": domain,
        "dns_resolves": False,
        "ip": None,
        "is_public_ip": False,
        "http_supported": False,
        "https_supported": False,
        "http2_supported": False,
        "server_version": "N/A",
        "ssl_status": "N/A",
        "ssl_issuer": "N/A",
        "ssl_expiry": "N/A",
        "title": "N/A"
    }

    try:
        ip = socket.gethostbyname(domain)
        result["dns_resolves"] = True
        result["ip"] = ip
    except socket.gaierror:
        return result

    try:
        ip_obj = ipaddress.ip_address(ip)
        result["is_public_ip"] = ip_obj.is_global
    except ValueError:
        pass

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Connection": "close"
    }

    # 1. HTTP Check
    try:
        conn = http.client.HTTPConnection(domain, timeout=5)
        conn.request("HEAD", "/", headers=headers)
        res = conn.getresponse()
        result["http_supported"] = True
        server_header = res.getheader('Server')
        if server_header:
            result["server_version"] = server_header
    except Exception:
        if verbose:
            traceback.print_exc()
        result["http_supported"] = False
    finally:
        try: 
            conn.close() 
        except Exception: 
            pass

    # 2a. HTTP/2 Detection (separate connection to avoid BadStatusLine)
    try:
        ctx_h2 = ssl._create_unverified_context() if ignore_ssl else ssl.create_default_context()
        ctx_h2.set_alpn_protocols(['h2', 'http/1.1'])
        conn_h2 = http.client.HTTPSConnection(domain, timeout=5, context=ctx_h2)
        conn_h2.connect()
        if conn_h2.sock:
            result["http2_supported"] = (conn_h2.sock.selected_alpn_protocol() == 'h2')
    except Exception:
        if verbose:
            traceback.print_exc()
    finally:
        try: 
            conn_h2.close() 
        except Exception: 
            pass

    # 2b. HTTPS Check (HTTP/1.1 only)
    try:
        ssl_context = ssl._create_unverified_context() if ignore_ssl else ssl.create_default_context()
        ssl_context.set_alpn_protocols(['http/1.1'])
        
        conn = http.client.HTTPSConnection(domain, timeout=5, context=ssl_context)
        conn.connect()
        result["https_supported"] = True
        
        if not ignore_ssl:
            result["ssl_status"] = "VALID"
            cert = conn.sock.getpeercert()
            if cert:
                result["ssl_issuer"] = parse_issuer(cert)
                result["ssl_expiry"] = parse_expiry(cert)
        else:
            result["ssl_status"] = "BYPASS (-k)"
            result["ssl_issuer"] = "(Hidden)"
            result["ssl_expiry"] = "(Hidden)"
        
        conn.request("HEAD", "/", headers=headers)
        res = conn.getresponse()
        server_header = res.getheader('Server')
        if server_header and result["server_version"] == "N/A":
            result["server_version"] = server_header
            
    except ssl.SSLError as e:
        result["https_supported"] = True 
        err_str = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in err_str:
            if "expired" in err_str.lower():
                result["ssl_status"] = "EXPIRED"
            elif "self signed" in err_str.lower():
                result["ssl_status"] = "SELF-SIGNED"
            else:
                result["ssl_status"] = "ERR_CERT"
        elif "hostname doesn't match" in err_str.lower():
            result["ssl_status"] = "ERR_HOSTNAME"
        elif "wrong version number" in err_str.lower():
            result["ssl_status"] = "ERR_TLS_VERS"
        else:
            result["ssl_status"] = "ERR_SSL"
    except TimeoutError:
        result["ssl_status"] = "TIMEOUT"
    except ConnectionRefusedError:
        result["https_supported"] = False
        result["ssl_status"] = "REFUSED"
    except OSError:
        result["https_supported"] = False
        result["ssl_status"] = "NO_HTTPS"
    except Exception as e:
        if verbose:
            traceback.print_exc()
        result["https_supported"] = False
        result["ssl_status"] = f"E:{type(e).__name__}"[:11]
    finally:
        try: 
            conn.close() 
        except Exception: 
            pass

    # 3. Extract Title with Follow Redirect
    if result["http_supported"] or result["https_supported"]:
        start_scheme = "https" if result["https_supported"] else "http"
        start_url = f"{start_scheme}://{domain}/"
        result["title"] = get_title_with_redirect(start_url, ignore_ssl, verbose)

    return result

def load_domains_from_file(filename: str) -> List[str]:
    if not os.path.exists(filename):
        print(f"Error: The file '{filename}' does not exist.")
        return []
    domains = []
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            clean_domain = line.strip()
            if clean_domain and not clean_domain.startswith("#"):
                domains.append(clean_domain)
    return domains

def main():
    parser = argparse.ArgumentParser(description="HTTP2Checker: DNS, IP, SSL, Server, Title and CSV export")
    parser.add_argument("domain", nargs="?", help="A single URL to check")
    parser.add_argument("-f", "--file", help="List of URLs to check, one per line")
    parser.add_argument("-k", "--insecure", action="store_true", help="Ignore SSL error")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show exception details for debugging")
    parser.add_argument("-o", "--output", help="Export on CSV")
    
    args = parser.parse_args()
    if not args.domain and not args.file:
        parser.print_help()
        return

    domain_list = [args.domain] if args.domain else load_domains_from_file(args.file)
    if not domain_list: return

    # CSV Writing configuration
    csv_file = None
    csv_writer = None
    if args.output:
        try:
            csv_file = open(args.output, mode='w', newline='', encoding='utf-8')
            csv_writer = csv.writer(csv_file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            # CSV Header writing
            csv_writer.writerow([
                "Domain", "DNS", "IP", "Public", "HTTP", "HTTPS", 
                "HTTP/2", "Server", "SSL Status", "Issuer", "Expiry", "Title"
            ])
            print(f"Results will be exported to: {args.output}")
        except Exception as e:
            print(f"Error opening CSV file: {e}")
            return

    # Initialize counters for the summary
    count_total = 0
    count_http = 0
    count_https = 0
    count_http2 = 0
    count_cert_valid = 0
    count_cert_expired = 0

    print("\nStarting analysis...\n")
    print(f"{'DOMAIN':<22} | {'IP':<15} | {'HTTP':<4} | {'HTTPS':<5} | {'H2':<3} | {'SERVER':<10} | {'SSL STATUS':<11} | {'ISSUER':<12} | {'EXPIRY':<10} | {'TITLE':<22}")
    print("-" * 133)

    for dom in domain_list:
        res = analyze_domain(dom, ignore_ssl=args.insecure, verbose=args.verbose)

        count_total += 1
        if res["http_supported"]: count_http += 1
        if res["https_supported"]: count_https += 1
        if res["http2_supported"]: count_http2 += 1
        if res["ssl_status"] == "VALID": count_cert_valid += 1
        if res["ssl_status"] == "EXPIRED": count_cert_expired += 1

        # Preparing variables for N/A logic if DNS fails
        dns_status = "OK" if res["dns_resolves"] else "FAIL"
        ip_str = res["ip"] if res["ip"] else "N/A"
        pub_status = "YES" if res["is_public_ip"] else "NO"
        http_status = "YES" if res["http_supported"] else "NO"
        https_status = "YES" if res["https_supported"] else "NO"
        h2_status = "YES" if res["http2_supported"] else "NO"
        server_str = res["server_version"]
        ssl_str = res["ssl_status"]
        issuer_str = res["ssl_issuer"]
        expiry_str = res["ssl_expiry"]
        title_str = res["title"]

        if not res["dns_resolves"]:
            pub_status = "N/A"
            http_status = "N/A"
            https_status = "N/A"
            h2_status = "N/A"
            server_str = "N/A"
            ssl_str = "N/A"
            issuer_str = "N/A"
            expiry_str = "N/A"
            title_str = "N/A"

        # Writing to CSV (data intact, without truncations)
        if csv_writer:
            csv_writer.writerow([
                res["domain"], dns_status, ip_str, pub_status,
                http_status, https_status, h2_status, server_str,
                ssl_str, issuer_str, expiry_str, title_str
            ])
            # Force disk write on every line
            csv_file.flush()

        # Truncating variables ONLY for screen output
        dom_print = dom if len(dom) <= 22 else dom[:19] + "..."
        server_print = server_str if len(server_str) <= 10 else server_str[:7] + "..."
        ssl_print = ssl_str if len(ssl_str) <= 11 else ssl_str[:11]
        issuer_print = issuer_str if len(issuer_str) <= 12 else issuer_str[:9] + "..."
        title_print = title_str if len(title_str) <= 22 else title_str[:19] + "..."

        print(f"{dom_print:<22} | {ip_str:<15} | {http_status:<4} | {https_status:<5} | {h2_status:<3} | {server_print:<10} | {ssl_print:<11} | {issuer_print:<12} | {expiry_str:<10} | {title_print:<22}")

    if csv_file:
        csv_file.close()
        print(f"\nExport completed. Data saved in: {args.output}")

    # Print Concluding Summary
    print("\n" + "=" * 50)
    print(f"{'ANALYSIS SUMMARY':^50}")
    print("=" * 50)
    print(f" Total Domains Analyzed : {count_total}")
    print(f" Domains with HTTP      : {count_http}")
    print(f" Domains with HTTPS     : {count_https}")
    print(f" Domains with HTTP/2    : {count_http2}")
    print(f" Valid Certificates     : {count_cert_valid}")
    print(f" Expired Certificates   : {count_cert_expired}")
    print("=" * 50 + "\n")

if __name__ == "__main__":
    main()
