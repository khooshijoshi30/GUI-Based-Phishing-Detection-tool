import re
import socket
import requests
import datetime
import logging
import idna
import tldextract
import dns.resolver
import whois
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup
import base64
import urllib.parse
import json
import folium  # For generating maps
import time

# === Logging Setup ===
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# === API KEYS ===
VIRUSTOTAL_API_KEY = '7a9b4a49e805d077543c8bf6efded38b8c47b33392cac4d792aa60106c2f6fb9'
GOOGLE_SAFE_BROWSING_API_KEY = 'AIzaSyBJAeyuEFMVag1CwftEU_nt3ENQoR1sH1A'
ABUSEIPDB_API_KEY = '884b6651c32a444b98778e9930617ca81d9e34a4e6d497feaf36a67b265fbba8c500696a4adf6295'
URLSCAN_API_KEY = '01983990-b31f-73ab-a6c1-fe9a0b0c6e81'
WHOISFREAKS_API_KEY = '80d3523e33844cebba7a81d2ac17e872'  # Your WhoisFreaks API key

# === Constants ===
KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
    'buff.ly', 'cutt.ly', 'rb.gy', 'shorte.st'
}

PHISHING_PHRASES = [
    "enter your password", "sign in to view document", "confirm your identity",
    "verify your account", "secure document", "update billing information",
    "your account has been suspended"
]

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'update', 'account', 'banking',
    'ebay', 'paypal'
]

# === Helper Functions ===
def normalize_url(url):
    parsed = urlparse(url, scheme='http')
    if not parsed.netloc:
        parsed = urlparse('http://' + url)
    return urlunparse(parsed)

def extract_domain(url):
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(parsed.netloc)
        domain = f"{ext.domain}.{ext.suffix}"
        return idna.decode(domain)
    except Exception as e:
        logger.warning(f"Failed to extract domain: {e}")
        return ""

def get_all_ip_addresses(domain):
    try:
        results = socket.getaddrinfo(domain, None)
        return list(set([info[4][0] for info in results]))
    except Exception as e:
        logger.warning(f"IP address resolution failed: {e}")
        return [f"Error: {e}"]

def has_ip_address(url):
    ipv4 = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url)
    ipv6 = re.search(r'\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b', url)
    return bool(ipv4 or ipv6)

def has_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def is_shortened_url(domain):
    return domain in KNOWN_SHORTENERS

def has_at_symbol(url):
    return '@' in url

def is_punycode(domain):
    return 'xn--' in domain

def has_many_subdomains(url):
    ext = tldextract.extract(urlparse(url).netloc)
    return ext.subdomain.count('.') >= 1  # Consider 2 or more subdomains as "many"

def has_hyphen(domain):
    return '-' in domain.split('.')[0]

# --- WHOIS caching ---
_whois_cache = {}

def get_whois_cached(domain):
    if domain not in _whois_cache:
        try:
            _whois_cache[domain] = whois.whois(domain)
        except Exception as e:
            logger.warning(f"WHOIS query failed for {domain}: {e}")
            _whois_cache[domain] = None
    return _whois_cache[domain]

def is_domain_young(domain):
    w = get_whois_cached(domain)
    if not w:
        return True  # Assume young if missing data or error
    creation_date = getattr(w, 'creation_date', None)
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if not isinstance(creation_date, datetime.datetime):
        return True
    now = datetime.datetime.now(datetime.timezone.utc)
    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
    age = (now - creation_date).days
    return age < 120

def has_dns_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return bool(answers)
    except Exception:
        return False

def contains_phishy_html(html):
    try:
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text().lower()
        return any(phrase in text for phrase in PHISHING_PHRASES)
    except Exception as e:
        logger.warning(f"HTML parsing failed: {e}")
        return False

def url_redirects_to_suspicious_domain(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_domain = extract_domain(response.url)
        original_domain = extract_domain(url)
        if final_domain != original_domain and has_suspicious_keywords(response.url):
            logger.info("URL redirects to suspicious domain.")
            return True
    except Exception as e:
        logger.warning(f"Redirect check failed: {e}")
    return False

def get_server_info(url):
    """
    Fetch HTTP server response headers and IP geolocation information.
    Returns formatted string summary.
    """
    try:
        if not url.lower().startswith(('http://', 'https://')):
            url = 'http://' + url

        response = requests.get(url, timeout=7, allow_redirects=True)
        headers = response.headers

        server_name = headers.get('Server', 'Unknown')
        powered_by = headers.get('X-Powered-By', 'Unknown')
        content_type = headers.get('Content-Type', 'Unknown')
        strict_transport = headers.get('Strict-Transport-Security', 'Not Present')
        connection = headers.get('Connection', 'Unknown')

        try:
            version = response.raw.version
            http_version = {10: 'HTTP/1.0', 11: 'HTTP/1.1', 20: 'HTTP/2'}.get(version, 'Unknown')
        except Exception:
            http_version = 'Unknown'

        final_url = response.url
        hostname = urlparse(final_url).hostname
        ip_address = socket.gethostbyname(hostname) if hostname else "Unknown"

        geo_info = {}
        geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        if geo_response.status_code == 200:
            geo_info = geo_response.json()

        location = f"{geo_info.get('city', 'Unknown City')}, {geo_info.get('regionName', 'Unknown Region')}, {geo_info.get('country', 'Unknown Country')}"
        isp = geo_info.get('isp', 'Unknown ISP')

        info = (
            f"Server Name: {server_name}\n"
            f"X-Powered-By: {powered_by}\n"
            f"Content-Type: {content_type}\n"
            f"Strict-Transport-Security: {strict_transport}\n"
            f"Connection: {connection}\n"
            f"HTTP Protocol: {http_version}\n"
            f"IP Address: {ip_address}\n"
            f"Location: {location}\n"
            f"ISP: {isp}\n"
        )
        return info

    except Exception as e:
        return f"Error retrieving server info: {e}"

def get_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=50)
        if resp.status_code != 200:
            return [f"Failed to query crt.sh (HTTP {resp.status_code})"]
        if not resp.text.strip():
            return [f"No data returned by crt.sh for {domain}"]
        data = resp.json()
        subdomains = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                if name.endswith(domain):
                    subdomains.add(name.strip())
        return sorted(subdomains) if subdomains else [f"No subdomains found for {domain}"]
    except Exception as e:
        return [f"Error retrieving subdomains: {e}"]

def get_ip_history(domain):
    try:
        resp = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=50)
        if "error" in resp.text.lower():
            return "IP History not available (possibly rate-limited)."
        return resp.text.strip()
    except Exception as e:
        return f"IP History error: {e}"

def get_dns_report(domain):
    try:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        results = []
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for r in answers:
                    results.append(f"{rtype}: {r}")
            except Exception:
                results.append(f"{rtype}: Not found.")
        return "\n".join(results)
    except Exception as e:
        return f"DNS Report error: {e}"

def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return None
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=5)
    except Exception:
        pass
    try:
        resp = requests.get(report_url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0)
            }
    except Exception:
        pass
    return None

def check_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return None
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {'key': GOOGLE_SAFE_BROWSING_API_KEY}
    try:
        resp = requests.post(endpoint, params=params, json=payload, timeout=5)
        if resp.status_code == 200:
            matches = resp.json().get('matches', [])
            return len(matches) > 0
    except Exception:
        pass
    return False

def fetch_openphish_feed():
    url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(url, timeout=50)
        if response.status_code == 200:
            return set(response.text.splitlines())
    except Exception:
        pass
    return set()

def check_openphish(url, openphish_feed):
    return url in openphish_feed

def check_abuseipdb(domain):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return None
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    try:
        resp = requests.get(endpoint, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data['data']['abuseConfidenceScore']
    except Exception:
        pass
    return None

# Improved URLScan query with domain validation, and corrected query for redirected URLs
def get_redirect_domains_urlscan(target_url, api_key):
    domain = extract_domain(target_url)
    if not domain or '.' not in domain:
        return ["Domain extraction failed or invalid for URLScan request."]
    
    raw_query = f'domain:{domain}'
    encoded_query = urllib.parse.quote(raw_query, safe=':')
    query_url = f"https://urlscan.io/api/v1/search/?q={encoded_query}"

    headers = {
        "API-Key": api_key,
        "User-Agent": "CID-Phishing-Tool/1.0"
        # Removed 'Content-Type' header which is unnecessary for GET
    }

    logger.info(f"URLScan query URL: {query_url}")
    
    try:
        resp = requests.get(query_url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('results', [])
            if not results:
                return ["No redirecting domains found."]
            domains = set()
            for entry in results:
                page_url = entry.get("page", {}).get("url")
                if page_url:
                    netloc = urlparse(page_url).netloc
                    if netloc:
                        domains.add(netloc)
            return sorted(domains) or ["No redirecting domains found."]
        elif resp.status_code == 429:
            return ["URLScan rate-limited: Too many requests"]
        elif resp.status_code == 400:
            return [f"URLScan API error 400: Bad request (domain: {domain}). This domain may not be indexed or accessible."]
        else:
            return [f"URLScan API Error: HTTP {resp.status_code}"]
    except Exception as e:
        return [f"Error retrieving redirect domains: {e}"]

def get_linked_pages(domain):
    url = f"https://web-check-latest.onrender.com/api/linked-pages?url={domain}"
    try:
        resp = requests.get(url, timeout=50)
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error retrieving linked pages: {e}"

# --- Improved domain to IP function with retries and fallback DNS lookup ---
def get_ip_from_domain(domain, max_retries=3, backoff_factor=2):
    url = f"http://web-check-latest.onrender.com/api/get-ip?url={domain}"
    attempt = 0
    while attempt < max_retries:
        try:
            resp = requests.get(url, timeout=50)
            resp.raise_for_status()
            data = resp.json()
            ip_info = data.get("A") or {}
            ip_address = ip_info.get("address") or data.get("ip")
            if ip_address:
                return json.dumps(data, indent=2), ip_address
            else:
                raise ValueError("No IP address found in API response.")
        except (requests.Timeout, requests.ConnectionError) as e:
            logger.warning(f"Domain-to-IP API timeout/error: {e}, retrying ({attempt+1}/{max_retries})")
            time.sleep(backoff_factor ** attempt)
            attempt += 1
        except Exception as e:
            logger.warning(f"Unexpected error during IP lookup for {domain}: {e}")
            break
    # Fallback: direct DNS resolution via socket
    try:
        ip_address = socket.gethostbyname(domain)
        return json.dumps({"ip": ip_address, "source": "fallback"}), ip_address
    except Exception as e:
        return f"Error retrieving IP from domain after retries: {e}", None

def get_geo_from_ip(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        resp = requests.get(url, timeout=50)
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(data, indent=2), data
    except Exception as e:
        return f"Error retrieving geolocation: {e}", None

def create_geo_map(lat, lon, domain):
    try:
        map_obj = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], popup=domain).add_to(map_obj)
        map_filename = f"{domain}_location_map.html"
        map_obj.save(map_filename)
        return map_filename
    except Exception as e:
        logger.warning(f"Map creation failed: {e}")
        return None

def reverse_whois_lookup_whoisfreaks(query):
    base_url = "https://www.whoisfreaks.com/reverse-whois-api.php"
    params = {
        "apiKey": WHOISFREAKS_API_KEY,
        "search": query,
        "limit": 50,
        "format": "json"
    }
    try:
        response = requests.get(base_url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if "domains" in data and isinstance(data["domains"], list):
            domains = [d.get("domain") for d in data["domains"] if "domain" in d]
            if domains:
                return sorted(domains)
            else:
                return ["No related domains found."]
        elif "error" in data:
            return [f"API error: {data['error']}"]
        else:
            return ["No related domains found or unexpected response."]
    except requests.exceptions.RequestException as e:
        return [f"Network/API error: {str(e)}"]
    except Exception as e:
        return [f"Unexpected error: {str(e)}"]

def calculate_phishing_score(url, openphish_feed=None):
    score = 0
    url = normalize_url(url)
    domain = extract_domain(url)
    if not domain:
        logger.warning("Failed to extract domain from URL; aborting phishing score calculation.")
        return {'score': 0, 'is_phishing': False, 'details': {}}

    ip_addresses = get_all_ip_addresses(domain)

    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        html = response.text
    except Exception:
        html = ""

    heuristics = [
        ('has_ip_address', has_ip_address, 2, url),
        ('has_suspicious_keywords', has_suspicious_keywords, 1, url),
        ('is_shortened_url', is_shortened_url, 2, domain),
        ('has_at_symbol', has_at_symbol, 1, url),
        ('is_punycode', is_punycode, 1, domain),
        ('has_many_subdomains', has_many_subdomains, 1, url),
        ('has_hyphen', has_hyphen, 1, domain),
        ('is_domain_young', is_domain_young, 2, domain),
        ('has_dns_record', has_dns_record, -2, domain),  # Negative weight; add score if no DNS record
        ('contains_phishy_html', contains_phishy_html, 2, html),
        ('url_redirects_to_suspicious_domain', url_redirects_to_suspicious_domain, 2, url),
    ]

    heuristics_results = {}
    for name, func, weight, param in heuristics:
        try:
            if name == 'is_domain_young':
                result = func(param)  # Uses WHOIS cache inside function
            else:
                result = func(param)
        except Exception as e:
            logger.warning(f"Heuristic {name} failed: {e}")
            result = False

        heuristics_results[name] = result

        # Special handling for DNS record: add score if no record
        if name == 'has_dns_record':
            if not result:
                score += 2
        elif result and weight > 0:
            score += weight

    vt_result = check_virustotal(url)
    gsafebrowsing = check_google_safe_browsing(url)
    openphish_detected = check_openphish(url, openphish_feed) if openphish_feed else False
    abuse_score = check_abuseipdb(domain)

    external_flag = False
    external_reason = []
    if vt_result and (vt_result.get('malicious', 0) > 0 or vt_result.get('suspicious', 0) > 0):
        external_flag = True
        external_reason.append("VirusTotal")
    if gsafebrowsing:
        external_flag = True
        external_reason.append("Google Safe Browsing")
    if openphish_detected:
        external_flag = True
        external_reason.append("OpenPhish")
    if abuse_score is not None and abuse_score >= 50:
        external_flag = True
        external_reason.append(f"AbuseIPDB ({abuse_score})")

    is_phishing = external_flag or (score >= 4)
    phishing_reason = "Flagged by: " + ", ".join(external_reason) if external_flag else ("Heuristic score threshold" if is_phishing else "No threat detected")

    subdomains = get_subdomains_crtsh(domain)
    ip_history = get_ip_history(domain)
    dns_report = get_dns_report(domain)
    redirect_domains = get_redirect_domains_urlscan(url, URLSCAN_API_KEY)
    linked_pages_json = get_linked_pages(domain)
    ip_json, ip_address = get_ip_from_domain(domain)
    geo_json, geo_data = (None, None)
    map_file = None
    if ip_address:
        geo_json, geo_data = get_geo_from_ip(ip_address)
        if geo_data and 'lat' in geo_data and 'lon' in geo_data:
            map_file = create_geo_map(geo_data['lat'], geo_data['lon'], domain)

    # Extract registrant email using cached WHOIS
    w = get_whois_cached(domain)
    registrant_email = None
    if w:
        if hasattr(w, 'emails') and w.emails:
            registrant_email = w.emails[0] if isinstance(w.emails, list) else w.emails
        elif hasattr(w, 'registrant_email') and w.registrant_email:
            registrant_email = w.registrant_email

    if registrant_email:
        reverse_whois_domains = reverse_whois_lookup_whoisfreaks(registrant_email)
    else:
        reverse_whois_domains = ["Registrant email not found; Reverse WHOIS lookup skipped"]

    details = {
        'ip_addresses': ip_addresses,
        'heuristics': heuristics_results,
        'virustotal': vt_result,
        'google_safe_browsing': gsafebrowsing,
        'openphish': openphish_detected,
        'abuseipdb_score': abuse_score,
        'phishing_reason': phishing_reason,
        'subdomains': subdomains,
        'ip_history': ip_history,
        'dns_report': dns_report,
        'redirect_domains': redirect_domains,
        'linked_pages_json': linked_pages_json,
        'ip_json': ip_json,
        'geo_json': geo_json,
        'map_file': map_file,
        'reverse_whois_domains': reverse_whois_domains,
    }

    return {
        'score': score,
        'is_phishing': is_phishing,
        'details': details
    }

# === Example usage ===
if __name__ == "__main__":
    test_url = "http://example.com"
    openphish_feed = fetch_openphish_feed()
    result = calculate_phishing_score(test_url, openphish_feed)
    print("========== Phishing Detection Report ==========")
    print(f"URL: {test_url}")
    print(f"Phishing Score: {result['score']}")
    print(f"Phishing Verdict: {'Phishing' if result['is_phishing'] else 'Safe'}")
    print(f"Reason: {result['details'].get('phishing_reason', '')}\n")
    print("--- Domain IP Addresses ---")
    for ip in result['details']['ip_addresses']:
        print(ip)
    print("\n--- Redirecting Domains (URLScan.io) ---")
    for d in result['details']['redirect_domains']:
        print(d)
    print("\n--- Linked Pages JSON ---")
    print(result['details'].get('linked_pages_json', 'No data'))
    print("\n--- Domain to IP JSON ---")
    print(result['details'].get('ip_json', 'No data'))
