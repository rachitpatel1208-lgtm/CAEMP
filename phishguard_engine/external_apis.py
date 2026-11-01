import os
import re
import socket
import ssl
import json
import logging
from urllib.parse import urlparse
import requests

logger = logging.getLogger(__name__)

# Keys from environment or config
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SAFEBROWSING_API_KEY = os.getenv("SAFEBROWSING_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

def check_dns_and_connectivity(hostname: str) -> dict:
    """
    Performs live DNS resolution and basic reachability check.
    """
    if not hostname:
        return {'resolved': False, 'ip': None, 'error': 'No hostname provided'}
    
    # Strip port if present
    clean_host = hostname.split(':')[0]
    
    try:
        ip = socket.gethostbyname(clean_host)
        return {
            'resolved': True,
            'ip': ip,
            'error': None,
            'message': f"Resolved to IP: {ip}"
        }
    except socket.gaierror as e:
        return {
            'resolved': False,
            'ip': None,
            'error': 'Domain not resolving (NXDOMAIN or dead host)',
            'message': 'Domain failed DNS resolution. Often indicates ephemeral or deactivated phishing domain.'
        }
    except Exception as e:
        return {
            'resolved': False,
            'ip': None,
            'error': str(e),
            'message': f"DNS check error: {e}"
        }

def check_ssl_certificate(hostname: str, timeout: float = 2.0) -> dict:
    """
    Checks if host supports SSL/TLS on port 443 and verifies certificate validity,
    protocol version, and issuer organization.
    """
    if not hostname:
        return {'has_ssl': False, 'valid': False, 'protocol': None, 'issuer': None, 'message': 'No hostname provided'}

    clean_host = hostname.split(':')[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert.get('issuer', [])) if cert else {}
                issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Trusted Certificate Authority'
                protocol = ssock.version()
                not_after = cert.get('notAfter', '') if cert else ''

                return {
                    'has_ssl': True,
                    'valid': True,
                    'protocol': protocol,
                    'issuer': issuer_name,
                    'expires': not_after,
                    'message': f"Valid SSL certificate ({protocol}) issued by {issuer_name}"
                }
    except ssl.SSLCertVerificationError as e:
        return {
            'has_ssl': True,
            'valid': False,
            'protocol': 'TLS',
            'issuer': 'Untrusted / Self-signed',
            'error': str(e),
            'message': 'Untrusted or self-signed SSL certificate'
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {
            'has_ssl': False,
            'valid': False,
            'protocol': None,
            'issuer': None,
            'error': str(e),
            'message': 'No SSL/HTTPS service responding on port 443'
        }
    except Exception as e:
        return {
            'has_ssl': False,
            'valid': False,
            'protocol': None,
            'issuer': None,
            'error': str(e),
            'message': f"SSL check error: {e}"
        }

def query_virustotal_url(url: str) -> dict:
    """
    Queries VirusTotal API v3 if API key is configured.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            'enabled': False,
            'checked': False,
            'message': 'VirusTotal API key not configured (Set VIRUSTOTAL_API_KEY in environment to enable live scans)'
        }

    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        resp = requests.get(endpoint, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            
            return {
                'enabled': True,
                'checked': True,
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'verdict': 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean',
                'raw_stats': stats
            }
        else:
            return {
                'enabled': True,
                'checked': False,
                'error': f"VirusTotal returned status {resp.status_code}"
            }
    except Exception as e:
        return {
            'enabled': True,
            'checked': False,
            'error': str(e)
        }

def query_google_safe_browsing(url: str) -> dict:
    """
    Queries Google Safe Browsing Lookup API v4 if configured.
    """
    if not SAFEBROWSING_API_KEY:
        return {
            'enabled': False,
            'checked': False,
            'message': 'Google Safe Browsing API key not configured (Set SAFEBROWSING_API_KEY in environment)'
        }

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFEBROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "PhishGuard", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get('matches', [])
            return {
                'enabled': True,
                'checked': True,
                'is_threat': len(matches) > 0,
                'threats': [m.get('threatType') for m in matches],
                'verdict': 'dangerous' if len(matches) > 0 else 'safe'
            }
        else:
            return {
                'enabled': True,
                'checked': False,
                'error': f"Safe Browsing API returned {resp.status_code}"
            }
    except Exception as e:
        return {
            'enabled': True,
            'checked': False,
            'error': str(e)
        }

def generate_ai_threat_intelligence(target_type: str, item: str, flags: list, models_summary: dict) -> dict:
    """
    Generates intelligent cyber threat explanation and actionable defensive recommendations.
    Can hook into Gemini API if GEMINI_API_KEY is present, or uses rich cybersecurity expert rules.
    """
    # Check if Gemini key is available for generative reasoning
    if GEMINI_API_KEY:
        try:
            # Query Gemini
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
            prompt = (
                f"You are PhishGuard Cybersecurity AI. Analyze this {target_type}: '{item}'.\n"
                f"Detected flags: {json.dumps(flags)}\n"
                f"Model consensus: {json.dumps(models_summary)}\n"
                f"Provide a 2-3 sentence expert threat analysis explaining why this is or isn't dangerous, "
                f"followed by 2 concrete protective steps."
            )
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            res = requests.post(endpoint, json=payload, timeout=6)
            if res.status_code == 200:
                gen_text = res.json()['candidates'][0]['content']['parts'][0]['text']
                return {
                    'engine': 'Gemini 1.5 Flash AI',
                    'explanation': gen_text.strip(),
                    'source': 'live_ai'
                }
        except Exception as e:
            logger.warning(f"Gemini API query failed or timed out: {e}")

    # Built-in Cyber Threat Intelligence Engine
    any_high = any(f.get('severity') == 'high' for f in flags)
    is_sus = models_summary.get('overall_threat_level') in ['suspicious', 'dangerous', 'critical'] or any_high

    if is_sus:
        reasons = []
        if any('impersonation' in str(f).lower() for f in flags):
            reasons.append("brand impersonation designed to mislead you into entering credentials")
        if any('urgency' in str(f).lower() for f in flags):
            reasons.append("manufactured urgency intended to bypass rational scrutiny")
        if any('ip' in str(f).lower() or 'tld' in str(f).lower() for f in flags):
            reasons.append("abnormal host infrastructure and high-risk top-level domain")
        if any('typo' in str(f).lower() or 'homoglyph' in str(f).lower() for f in flags):
            reasons.append("deceptive domain typosquatting visually mimicking a trusted brand")
        
        reason_str = ", ".join(reasons) if reasons else "multiple anomalous lexical and heuristic risk indicators"
        
        explanation = (
            f"PhishGuard Multi-Model Intelligence identified high-probability social engineering signals. "
            f"The analyzed artifact exhibits {reason_str}. "
            f"Multiple independent detection models agreed on this elevated risk classification."
        )
        recommendations = [
            "Do not click links, open attachments, or input personal/financial credentials.",
            "Verify the communication independently via official channels or bookmark links.",
            "Report the sender/URL to your organization's IT security team or PhishTank/Google Safe Browsing."
        ]
    else:
        explanation = (
            "PhishGuard Multi-Model Intelligence evaluated this item across all lexical, structural, and NLP classifiers. "
            "No prominent phishing indicators, deceptive patterns, or known malicious anomalies were detected."
        )
        recommendations = [
            "Proceed normally, but always exercise caution before sharing sensitive credentials.",
            "Check for valid HTTPS lock icon and verify the address bar domain matches the destination."
        ]

    return {
        'engine': 'PhishGuard Cyber AI Heuristic Engine',
        'explanation': explanation,
        'recommendations': recommendations,
        'source': 'rule_ai'
    }
