import re
from urllib.parse import urlparse

def extract_features(url):
    features = []

    # 1. Length of URL
    features.append(len(url))

    # 2. HTTPS presence
    features.append(1 if "https" in url else 0)

    # 3. Number of dots
    features.append(url.count("."))

    # 4. '@' symbol
    features.append(1 if "@" in url else 0)

    # 5. Hyphen in domain
    domain = urlparse(url).netloc
    features.append(1 if "-" in domain else 0)

    # -------- NEW FEATURES -------- #

    # 6. IP address in URL
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)

    # 7. Number of special characters
    features.append(sum([1 for c in url if c in ['@', '-', '_', '?', '=', '&']]))

    # 8. Length of domain
    features.append(len(domain))

    # 9. Suspicious keywords
    keywords = ['login', 'secure', 'bank', 'verify', 'account']
    features.append(1 if any(word in url.lower() for word in keywords) else 0)

    # 10. Number of subdomains
    features.append(domain.count("."))

    # 11. HTTP (not HTTPS)
    features.append(1 if url.startswith("http://") else 0)

    # 12. Double slash in path
    features.append(1 if '//' in url[7:] else 0)

    # 13. Suspicious TLD
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    features.append(1 if any(tld in url for tld in suspicious_tlds) else 0)

    return features
