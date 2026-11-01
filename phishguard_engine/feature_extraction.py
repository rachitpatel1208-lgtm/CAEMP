import re
import math
from urllib.parse import urlparse

# Suspicious TLDs often abused in phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'click',
    'fit', 'country', 'stream', 'kim', 'loan', 'club', 'vip', 'monster',
    'rest', 'surf', 'icu', 'cam', 'casa', 'link', 'live', 'support', 'bar'
}

# Known URL shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy'
}

# High-risk phishing keywords
PHISHING_KEYWORDS = [
    'login', 'verify', 'account', 'banking', 'secure', 'update', 'signin',
    'webscr', 'ebayisapi', 'support', 'confirm', 'security', 'wallet',
    'token', 'recover', 'password', 'validation', 'billing', 'unlock',
    'suspended', 'authorize', 'chase', 'paypal', 'apple', 'microsoft',
    'netflix', 'amazon', 'wellsfargo', 'bankofamerica'
]

def shannon_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string (measures randomness)."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_url_features(raw_url: str, ssl_active: bool = False) -> dict:
    """
    Extracts numerical & boolean lexical features from a raw URL.
    Returns a dictionary of named features suitable for tabular ML models.
    """
    url = str(raw_url).strip()
    if not url.startswith(('http://', 'https://')):
        url_with_scheme = ('https://' if ssl_active else 'http://') + url
    else:
        url_with_scheme = url

    try:
        parsed = urlparse(url_with_scheme)
        hostname = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = ''
        path = ''
        query = ''

    url_lower = url.lower()
    tld = hostname.split('.')[-1] if '.' in hostname else ''

    # Checks
    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    is_shortener = 1 if hostname in URL_SHORTENERS else 0
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    has_https = 1 if (raw_url.lower().startswith('https://') or ssl_active) else 0
    has_port = 1 if parsed.port is not None else 0

    # Counts
    dots = url.count('.')
    hyphens = url.count('-')
    slashes = url.count('/')
    at_symbols = url.count('@')
    questions = url.count('?')
    equals = url.count('=')
    percents = url.count('%')
    underscores = url.count('_')
    tildes = url.count('~')

    url_len = len(url)
    hostname_len = len(hostname)
    path_len = len(path)

    # Digit ratios
    digits_in_url = sum(c.isdigit() for c in url)
    digits_in_host = sum(c.isdigit() for c in hostname)
    ratio_digits_url = digits_in_url / max(url_len, 1)
    ratio_digits_host = digits_in_host / max(hostname_len, 1)

    # Subdomain depth
    subdomain_parts = hostname.split('.')
    subdomain_count = max(0, len(subdomain_parts) - 2) if len(subdomain_parts) > 1 else 0

    # Entropy
    domain_entropy = shannon_entropy(hostname)
    url_entropy = shannon_entropy(url)

    # Phishing keyword count
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)

    # Consecutive suspicious chars
    has_consecutive_hyphens = 1 if '--' in url else 0
    has_double_slash_in_path = 1 if '//' in path else 0

    return {
        'url_length': url_len,
        'hostname_length': hostname_len,
        'path_length': path_len,
        'count_dots': dots,
        'count_hyphens': hyphens,
        'count_slashes': slashes,
        'count_at': at_symbols,
        'count_question': questions,
        'count_equals': equals,
        'count_percent': percents,
        'count_underscore': underscores,
        'count_tilde': tildes,
        'ratio_digits_url': round(ratio_digits_url, 4),
        'ratio_digits_host': round(ratio_digits_host, 4),
        'is_ip': is_ip,
        'is_shortener': is_shortener,
        'is_suspicious_tld': is_suspicious_tld,
        'has_https': has_https,
        'has_port': has_port,
        'subdomain_count': subdomain_count,
        'domain_entropy': round(domain_entropy, 4),
        'url_entropy': round(url_entropy, 4),
        'phishing_keyword_count': keyword_count,
        'has_consecutive_hyphens': has_consecutive_hyphens,
        'has_double_slash_in_path': has_double_slash_in_path
    }

FEATURE_NAMES = list(extract_url_features('http://example.com').keys())

def extract_features_vector(raw_url: str) -> list:
    """Extracts URL features as a flat numerical vector for scikit-learn models."""
    feat_dict = extract_url_features(raw_url)
    return [feat_dict[k] for k in FEATURE_NAMES]
