import re
import sys
import quopri
import hashlib
import ipaddress
import requests
import email
import unicodedata
import idna
import socket
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr


def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content)
    return msg

def extract_ips(email_message):
    ips = set()
    
    # Extract IP addresses from headers
    for header_name, header_value in email_message.items():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    
    # Extract IP addresses from email body
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(set(valid_ips))

def extract_urls(email_message):
    urls = set()
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(urls)

def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    url = url.replace('https://', 'hxxps[://]')
    url = url.replace('.', '[.]')
    return url

def is_reserved_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ip_lookup(ip):
    if is_reserved_ip(ip):
        return None

    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'IP': data.get('ip', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'Location': data.get('loc', ''),
                'ISP': data.get('org', ''),
                'Postal Code': data.get('postal', '')
            }
    except (requests.RequestException, ValueError) as e:
        # Log the error if needed or simply pass
        pass

    return None

def extract_headers(email_message):
    headers_to_extract = [
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers = {}
    for key in email_message.keys():
        if key in headers_to_extract:
            headers[key] = email_message[key]
    return headers

def extract_attachments(email_message):
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            attachments.append({
                'filename': filename,
                'md5': hashlib.md5(part.get_payload(decode=True)).hexdigest(),
                'sha1': hashlib.sha1(part.get_payload(decode=True)).hexdigest(),
                'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            })
    return attachments

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "tiny.cc",
    "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "gq",
    "tk",
    "ml",
    "work",
    "top",
    "xyz",
}

PHISHING_KEYWORDS = {
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "password",
    "wallet",
    "signin",
    "auth",
    "payment",
    "invoice",
    "crypto",
}


def analyze_urls(urls):
    matches = 0

    for url in urls:
        try:
            parsed = urlparse(url)

            domain = parsed.netloc.lower()
            domain = domain.split(":")[0]

            full_url = url.lower()


            if domain in SHORTENERS:
                matches += 1


            try:
                socket.inet_aton(domain)
                matches += 1
            except:
                pass


            parts = domain.split(".")

            if parts:
                tld = parts[-1]

                if tld in SUSPICIOUS_TLDS:
                    matches += 1


            if len(parts) > 4:
                matches += 1


            for keyword in PHISHING_KEYWORDS:
                if keyword in full_url:
                    matches += 1


            if "@" in parsed.netloc:
                matches += 1


            if "xn--" in domain:
                matches += 1


            if len(url) > 200:
                matches += 1


            if parsed.scheme == "http":
                matches += 1

        except:
            matches += 1


    if matches == 0:
        risk = "UNKNOWN"
    elif matches <= 2:
        risk = "MEDIUM"
    elif matches <= 5:
        risk = "HIGH"
    else:
        risk = "CRITICAL"

    print(f"URLs Risk Level       :  {risk}")

def analyze_eml(file_path):

    PHISHING_PHRASES = [

        # Urgency
        "action required",
        "urgent",
        "urgent response needed",
        "immediate action required",
        "final warning",
        "critical notice",
        "respond immediately",
        "time sensitive",
        "act now",
        "failure to respond",

        # Account
        "verify your account",
        "confirm your account",
        "validate your account",
        "security verification",
        "identity confirmation",
        "password expired",
        "account locked",
        "account suspended",
        "unusual activity",
        "suspicious activity",

        # Credential harvesting
        "login required",
        "click here",
        "sign in",
        "login here",
        "verify now",
        "update now",
        "confirm your password",
        "secure message",
        "open attachment",
        "view document",
        "shared document",

        # Financial
        "payment required",
        "invoice attached",
        "payment failed",
        "wire transfer",
        "bank transfer",
        "transaction failed",
        "refund available",

        # BEC
        "are you available",
        "quick favor",
        "gift cards",
        "send me the codes",
        "confidential request",

        # Delivery scams
        "package delivery failed",
        "track your package",
        "delivery attempt failed",

        # Security
        "security alert",
        "security breach",
        "unauthorized login attempt",

        # Crypto scams
        "wallet verification",
        "confirm seed phrase",

        # Sextortion
        "i recorded you",
        "send bitcoin",
    ]



    try:

        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

    except Exception as e:

        print(f"[ERROR] Failed to load EML: {e}")
        return



    subject = msg.get("subject", "")

    body = ""

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:
                    body += part.get_content()

                except:
                    pass

    else:

        try:
            body = msg.get_content()

        except:
            pass

    full_text = f"{subject}\n{body}".lower()


    findings = []
    total_hits = 0

    for phrase in PHISHING_PHRASES:

        matches = re.findall(re.escape(phrase), full_text)

        if matches:

            count = len(matches)

            findings.append({
                "phrase": phrase,
                "count": count
            })

            total_hits += count


    if total_hits == 0:
        risk = "LOW"

    elif total_hits <= 3:
        risk = "MEDIUM"

    elif total_hits <= 7:
        risk = "HIGH"

    else:
        risk = "CRITICAL"


    if findings:
        total_hits = str(total_hits)
        print("Pattern Analysis       : Detected "+total_hits+" keyword(s)   Risk Level: "+risk+"   Subject: '"+subject+"'")

        for item in findings:
            '''
            print(
                f"  - '{item['phrase']}' "
                f"(x{item['count']})"
            )
            '''
    else:

        print("Pattern Analysis: No phishing phrases detected.")


KNOWN_SCRIPTS = [
    "LATIN",
    "CYRILLIC",
    "GREEK",
    "ARMENIAN",
    "HEBREW",
    "ARABIC",
    "DEVANAGARI",
    "HIRAGANA",
    "KATAKANA",
    "HANGUL",
    "CJK"
]

CONFUSABLES = {
    'а': 'a',  
    'е': 'e',
    'о': 'o',
    'р': 'p',
    'с': 'c',
    'у': 'y',
    'х': 'x',
    'і': 'i',
    'ј': 'j',
    'ӏ': 'l',
    'ԁ': 'd',
    'ｍ': 'm', 
    'ｏ': 'o',
    'ｌ': 'l',
}


def extract_domain(text):
    """
    Extract hostname from URL or raw domain.
    """

    text = text.strip()

    if "://" not in text:
        text = "http://" + text

    parsed = urlparse(text)

    domain = parsed.hostname

    if not domain:
        return None

    return domain.lower()


def get_script(char):
    """
    Determine Unicode script family.
    """

    if ord(char) < 128:
        return "LATIN"

    try:
        name = unicodedata.name(char)

        for script in KNOWN_SCRIPTS:
            if script in name:
                return script

        return "OTHER"

    except ValueError:
        return "UNKNOWN"


def decode_punycode(domain):
    """
    Decode xn-- domains into Unicode.
    """

    try:
        return idna.decode(domain)
    except Exception:
        return domain


def encode_punycode(domain):
    """
    Convert Unicode domain into punycode.
    """

    try:
        return idna.encode(domain).decode("ascii")
    except Exception as e:
        return f"ERROR: {e}"


def analyze_domain(domain):

    unicode_domain = decode_punycode(domain)
    punycode = encode_punycode(unicode_domain)

    scripts = set()
    suspicious_chars = []
    confusable_hits = []

    for char in unicode_domain:

        if char in ".-":
            continue

        script = get_script(char)
        scripts.add(script)

        if ord(char) > 127:
            suspicious_chars.append({
                "char": char,
                "script": script,
                "unicode": f"U+{ord(char):04X}"
            })

        if char in CONFUSABLES:
            confusable_hits.append({
                "char": char,
                "looks_like": CONFUSABLES[char],
                "script": script,
                "unicode": f"U+{ord(char):04X}"
            })


    risk = "LOW"
    reasons = []

    if suspicious_chars:
        risk = "MEDIUM"
        reasons.append("Contains non-ASCII characters")

    meaningful_scripts = {
        s for s in scripts
        if s not in ("LATIN", "OTHER", "UNKNOWN")
    }

    if "LATIN" in scripts and meaningful_scripts:
        risk = "HIGH"
        reasons.append("Mixed Latin and non-Latin scripts detected")

    if confusable_hits:
        risk = "CRITICAL"
        reasons.append("Contains known homoglyph/confusable characters")

    return {
        "domain": domain,
        "unicode_domain": unicode_domain,
        "punycode": punycode,
        "scripts": sorted(list(scripts)),
        "risk": risk,
        "reasons": reasons,
        "suspicious_chars": suspicious_chars,
        "confusable_hits": confusable_hits
    }


def print_report(result):


    print(f"Homoglyph Attack Risk Level       : {result['risk']}")

def extract_domain(eml_path):
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    from_header = msg.get("From", "")

    name, email_addr = parseaddr(from_header)

    if not email_addr:
        return None

    domain = email_addr.split("@")[-1].lower()

    return domain
    

def main(file_path):
    email_message = read_file(file_path)
    ips = extract_ips(email_message)
    urls = extract_urls(email_message)
    headers = extract_headers(email_message)
    attachments = extract_attachments(email_message)

    print("Extracted IP Addresses:")
    print("====================================")
    for ip in ips:
        defanged_ip = defang_ip(ip)
        ip_info = ip_lookup(ip)
        if ip_info:
            print(f"{defanged_ip} - {ip_info['City']}, {ip_info['Region']}, {ip_info['Country']}, ISP: {ip_info['ISP']}")
        else:
            print(defanged_ip)

    print("\nExtracted URLs:")
    print("====================================")
    for url in urls:
        print(defang_url(url))

    print("\nExtracted Headers:")
    print("====================================")
    for key, value in headers.items():
        print(f"{key}: {value}")

    print("\nExtracted Attachments:")
    print("====================================")
    for attachment in attachments:
        print(f"Filename: {attachment['filename']}")
        print(f"MD5: {attachment['md5']}")
        print(f"SHA1: {attachment['sha1']}")
        print(f"SHA256: {attachment['sha256']}")
        print()

    print("\nEmail legitimacy auto-validation:")
    print("====================================")
    ev = 1
    domain = extract_domain(sys.argv[1])
    result = analyze_domain(domain)
    print_report(result)
    for key, value in headers.items():
        if key == "To":
            domainMe = value.split('@')[1]
            me = domainMe
        else:
            continue
    if me != domain:
        print("Sender Origin       : External!!!")
    else:
        print("Sender Origin       :  Internal")
    analyze_eml(file_path)
    for url in urls:
        analyze_urls(url)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)