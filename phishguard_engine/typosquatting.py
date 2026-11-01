import re
from urllib.parse import urlparse

# Major targeted brands and their official legitimate primary domains
BRAND_DOMAINS = {
    "google": ["google.com", "google.co.uk", "google.co.in", "google.ca", "google.de", "google.fr", "google.com.br", "google.co.jp"],
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "msn.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank": ["citi.com", "citibank.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
    "dropbox": ["dropbox.com"],
    "spotify": ["spotify.com"],
    "youtube": ["youtube.com"],
    "yahoo": ["yahoo.com"],
    "ebay": ["ebay.com"],
    "walmart": ["walmart.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg"],
    "telegram": ["telegram.org", "t.me"],
    "adobe": ["adobe.com"],
    "zoom": ["zoom.us"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "dhl": ["dhl.com"],
    "usps": ["usps.com"],
    "reddit": ["reddit.com"],
    "wikipedia": ["wikipedia.org"]
}

# Homoglyph and lookalike character mapping
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', 'l': 'i', 'i': 'l',
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'і': 'i',
    'ν': 'v', 'τ': 't', 'ı': 'i', 'ɡ': 'g', 'ß': 'b', 'ʀ': 'r'
}

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculates Damerau-Levenshtein distance (insertions, deletions, substitutions,
    and transposition of two adjacent characters).
    """
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,          # deletion
                d[(i, j - 1)] + 1,          # insertion
                d[(i - 1, j - 1)] + cost    # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + cost) # transposition

    return d[(len1 - 1, len2 - 1)]

def normalize_confusables(s: str) -> str:
    """Replaces common visual confusable characters and patterns."""
    res = s.lower()
    res = res.replace('rn', 'm')
    res = res.replace('vv', 'w')
    res = res.replace('cl', 'd')
    res = res.replace('nn', 'm')
    for char, replacement in HOMOGLYPH_MAP.items():
        res = res.replace(char, replacement)
    return res

def extract_domain_parts(raw_url: str):
    """Parses URL into full hostname, root domain (SLD+TLD), and main SLD name."""
    url = str(raw_url).strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
    except Exception:
        hostname = ''

    parts = hostname.split('.')
    if len(parts) >= 2:
        # Check two-part TLDs like .co.uk
        if len(parts) >= 3 and parts[-2] in {'co', 'com', 'org', 'net', 'gov', 'edu'}:
            root_domain = '.'.join(parts[-3:])
            sld = parts[-3]
        else:
            root_domain = '.'.join(parts[-2:])
            sld = parts[-2]
    else:
        root_domain = hostname
        sld = hostname

    return hostname, root_domain, sld

def check_typosquatting(raw_url: str) -> dict:
    """
    Examines if a domain is a typosquatted, lookalike, or combosquatted variation
    of a major legitimate brand.
    """
    hostname, root_domain, sld = extract_domain_parts(raw_url)
    if not sld or not root_domain:
        return {'is_typosquat': False}

    # 1. First check if it is genuinely the official legitimate domain of that brand
    for brand, official_domains in BRAND_DOMAINS.items():
        if root_domain in official_domains:
            # Check for subdomain deception: e.g. "google.com.malicious.xyz"
            # Here root_domain is legitimate (e.g. google.com), so this is safe!
            return {
                'is_typosquat': False,
                'is_official': True,
                'brand': brand,
                'official_domain': root_domain
            }

    normalized_sld = normalize_confusables(sld)

    # 2. Check for exact visual homoglyphs (e.g., g00gle, paypa1)
    for brand, official_domains in BRAND_DOMAINS.items():
        target_name = brand.lower()
        official_domain = official_domains[0]

        # Check if normalized version matches brand name but original does not
        if normalized_sld == target_name and sld != target_name:
            return {
                'is_typosquat': True,
                'brand': brand.capitalize(),
                'legitimate_domain': official_domain,
                'technique': f'Visual Homoglyph Spoofing ({sld} mimics {brand})',
                'edit_distance': 1,
                'confidence': 99,
                'warning': f"Deceptive lookalike domain detected! '{root_domain}' uses visual character substitution to impersonate '{official_domain}'."
            }

    # 3. Check for Character Elongation / Stretch-Squatting (e.g., gooooogle, paypaaaal, amazzzon, appleeee)
    collapsed_2 = re.sub(r'(.)\1+', r'\1\1', normalized_sld)
    collapsed_1 = re.sub(r'(.)\1+', r'\1', normalized_sld)
    dehyphenated = normalized_sld.replace('-', '')

    for brand, official_domains in BRAND_DOMAINS.items():
        target_name = brand.lower()
        official_domain = official_domains[0]

        # Collapsed repeating characters match brand exactly
        if (collapsed_2 == target_name or collapsed_1 == target_name or dehyphenated == target_name) and sld != target_name:
            return {
                'is_typosquat': True,
                'brand': brand.capitalize(),
                'legitimate_domain': official_domain,
                'technique': f"Character Elongation / Padding typo ('{sld}' repeats letters of '{target_name}')",
                'edit_distance': abs(len(sld) - len(target_name)),
                'confidence': 98,
                'warning': f"Stretch-squatting detected! '{root_domain}' pads repeating characters to mimic legitimate brand '{official_domain}'."
            }

        # Subsequence with only duplicate brand letters
        if len(sld) > len(target_name) and len(sld) <= len(target_name) + 10:
            it = iter(normalized_sld)
            if all(ch in it for ch in target_name) and set(normalized_sld.replace('-', '')).issubset(set(target_name)):
                return {
                    'is_typosquat': True,
                    'brand': brand.capitalize(),
                    'legitimate_domain': official_domain,
                    'technique': f"Character Elongation / Padding typo ('{sld}' stretches '{target_name}')",
                    'edit_distance': len(sld) - len(target_name),
                    'confidence': 96,
                    'warning': f"Stretch-squatting detected! '{root_domain}' uses elongated characters to impersonate '{official_domain}'."
                }

    # 4. Check Levenshtein edit distance on core SLD (e.g., goggle vs google, microsft vs microsoft)
    for brand, official_domains in BRAND_DOMAINS.items():
        target_name = brand.lower()
        official_domain = official_domains[0]
        
        # Don't match short 3-letter brands with loose edit distance
        max_allowed_distance = 1 if len(target_name) <= 5 else 2
        
        dist = damerau_levenshtein_distance(sld, target_name)
        norm_dist = damerau_levenshtein_distance(normalized_sld, target_name)
        min_dist = min(dist, norm_dist)

        # Disallow exact matches (dist == 0) here because we already checked official domains above
        # If dist == 0, it means sld == brand, but root_domain is NOT in official_domains (e.g., google.xyz or paypal.top)
        if min_dist == 0:
            return {
                'is_typosquat': True,
                'brand': brand.capitalize(),
                'legitimate_domain': official_domain,
                'technique': f'Unauthorized Brand Domain TLD Hijack ({root_domain} vs {official_domain})',
                'edit_distance': 0,
                'confidence': 98,
                'warning': f"Unauthorized brand name usage! '{root_domain}' uses the trademarked name '{brand}' under an unofficial TLD."
            }

        if min_dist <= max_allowed_distance:
            # Determine specific typo technique
            if len(sld) < len(target_name):
                technique = f"Character Omission typo ('{sld}' missing letter from '{target_name}')"
            elif len(sld) > len(target_name):
                technique = f"Character Insertion typo ('{sld}' extra letter added to '{target_name}')"
            elif sorted(list(sld)) == sorted(list(target_name)):
                technique = f"Adjacent Character Transposition typo ('{sld}' transposed from '{target_name}')"
            else:
                technique = f"Character Substitution / Misspelling typo ('{sld}' substituted for '{target_name}')"

            return {
                'is_typosquat': True,
                'brand': brand.capitalize(),
                'legitimate_domain': official_domain,
                'technique': technique,
                'edit_distance': min_dist,
                'confidence': 95 if min_dist == 1 else 88,
                'warning': f"Typosquatting detected! '{root_domain}' is a visual lookalike/misspelling of '{official_domain}'."
            }

    # 4. Check for Combosquatting / Subdomain deception
    # e.g., "google-security-login.com" or "paypal-update.xyz" or "login.google.com.xyz"
    for brand, official_domains in BRAND_DOMAINS.items():
        target_name = brand.lower()
        official_domain = official_domains[0]

        # Is the brand name embedded in the domain or subdomain?
        if target_name in hostname:
            # But the root domain is NOT official
            if root_domain not in official_domains:
                return {
                    'is_typosquat': True,
                    'brand': brand.capitalize(),
                    'legitimate_domain': official_domain,
                    'technique': f'Combosquatting / Brand Name Embedding ({target_name} inside {root_domain})',
                    'edit_distance': 0,
                    'confidence': 92,
                    'warning': f"Brand impersonation detected! Domain '{hostname}' incorporates '{brand}' but does not belong to the official '{official_domain}' infrastructure."
                }

    return {'is_typosquat': False}
