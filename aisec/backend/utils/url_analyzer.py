"""
URL Analyzer - Core engine for phishing URL detection.
Uses a 21-feature rule-based scoring system (ML model loaded if available).
"""
import re
import math
import pickle
import os
from urllib.parse import urlparse
from datetime import datetime

# Top 500 brands for impersonation detection
TOP_BRANDS = [
    "google", "microsoft", "apple", "amazon", "facebook", "paypal", "netflix",
    "instagram", "twitter", "linkedin", "dropbox", "github", "adobe", "zoom",
    "slack", "salesforce", "oracle", "sap", "shopify", "stripe", "twilio",
    "okta", "cloudflare", "godaddy", "namecheap", "hostgator", "bluehost",
    "wordpress", "wix", "squarespace", "hubspot", "mailchimp", "sendgrid",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
    "americanexpress", "visa", "mastercard", "irs", "usps", "fedex", "ups",
    "dhl", "ebay", "walmart", "target", "bestbuy", "costco", "homedepot",
    "att", "verizon", "tmobile", "comcast", "xfinity", "spectrum",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".live", ".online", ".site", ".website", ".space", ".fun", ".icu",
    ".buzz", ".cyou", ".bond", ".hair", ".monster", ".rest",
}

URGENCY_KEYWORDS = [
    "verify", "suspend", "urgent", "immediately", "expire", "limited",
    "click here", "login", "confirm", "unusual", "security alert",
    "account locked", "update required", "action required",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")


def load_model():
    """Load pre-trained XGBoost model if available."""
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    return None


def calculate_entropy(text: str) -> float:
    """Shannon entropy of a string - high entropy = random/obfuscated."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def detect_homoglyphs(domain: str) -> list[str]:
    """Detect lookalike character substitutions."""
    findings = []
    homoglyphs = {
        "rn": "m", "vv": "w", "0": "o", "1": "l", "3": "e",
        "4": "a", "@": "a", "5": "s", "6": "g", "8": "b",
    }
    for fake, real in homoglyphs.items():
        if fake in domain:
            findings.append(f"'{fake}' used instead of '{real}'")
    return findings


def check_brand_impersonation(domain: str) -> dict:
    """Check if domain impersonates a known brand."""
    domain_clean = re.sub(r'[0-9@\-_.]', '', domain.lower())
    
    for brand in TOP_BRANDS:
        brand_clean = brand.replace('-', '')
        # Exact brand name in domain with extra content
        if brand_clean in domain_clean and domain_clean != brand_clean:
            return {"impersonates": brand, "method": "brand_name_in_domain"}
        # Fuzzy match - brand without last char (e.g. "googl" for "google")
        if len(brand_clean) > 4 and brand_clean[:-1] in domain_clean:
            return {"impersonates": brand, "method": "partial_brand_match"}
    
    return {}


def extract_features(url: str) -> dict:
    """Extract 21 ML features from a URL."""
    try:
        parsed = urlparse(url if url.startswith(('http', 'ftp')) else f"https://{url}")
    except Exception:
        parsed = urlparse(f"https://{url}")

    domain = parsed.netloc or parsed.path
    path = parsed.path
    query = parsed.query
    full_url = url

    # Remove www
    domain_clean = re.sub(r'^www\.', '', domain.lower())
    
    # TLD extraction
    tld_match = re.search(r'\.[a-z]{2,}$', domain_clean)
    tld = tld_match.group(0) if tld_match else ''
    
    subdomains = domain_clean.split('.')[:-2] if len(domain_clean.split('.')) > 2 else []

    features = {
        # Length-based
        "url_length": len(full_url),
        "domain_length": len(domain_clean),
        "path_length": len(path),
        
        # Character ratios
        "special_char_ratio": len(re.findall(r'[^a-zA-Z0-9]', full_url)) / max(len(full_url), 1),
        "digit_ratio": len(re.findall(r'\d', domain_clean)) / max(len(domain_clean), 1),
        "hyphen_count": domain_clean.count('-'),
        "dot_count": full_url.count('.'),
        
        # Suspicious indicators
        "has_at_symbol": int('@' in full_url),
        "has_ip_address": int(bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))),
        "has_https": int(parsed.scheme == 'https'),
        "has_double_slash": int('//' in path),
        "subdomain_count": len(subdomains),
        
        # TLD
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "tld": tld,
        
        # Entropy
        "domain_entropy": round(calculate_entropy(domain_clean), 3),
        "path_entropy": round(calculate_entropy(path), 3),
        
        # Brand signals
        "brand_impersonation": check_brand_impersonation(domain_clean),
        "homoglyphs": detect_homoglyphs(domain_clean),
        
        # Query params
        "query_param_count": len(re.findall(r'&|\?', query)),
        "has_redirect_param": int(any(k in query.lower() for k in ['redirect', 'url=', 'return', 'next='])),
        
        # Domain age proxy (heuristic - real impl uses whois)
        "domain_newly_registered_proxy": int(len(domain_clean) < 8 or tld in SUSPICIOUS_TLDS),
        
        # Parsed domain
        "domain": domain_clean,
        "path": path,
    }

    return features


def score_url(features: dict) -> tuple[int, list[str], str]:
    """Rule-based scoring engine returning (score, timeline_steps, verdict)."""
    score = 0
    timeline = []
    
    # Try ML model first
    model = load_model()
    if model:
        try:
            feature_vector = [
                features["url_length"], features["domain_length"],
                features["special_char_ratio"], features["digit_ratio"],
                features["hyphen_count"], features["dot_count"],
                features["has_at_symbol"], features["has_ip_address"],
                features["has_https"], features["subdomain_count"],
                features["suspicious_tld"], features["domain_entropy"],
                features["path_entropy"], features["query_param_count"],
                features["has_redirect_param"],
            ]
            ml_score = int(model.predict_proba([feature_vector])[0][1] * 100)
            score = ml_score
        except Exception:
            model = None  # Fall back to rules
    
    if not model:
        # Rule-based scoring
        
        # URL length (>75 chars suspicious)
        if features["url_length"] > 100:
            score += 15
            timeline.append(f"🔍 URL is unusually long ({features['url_length']} characters) — legitimate sites rarely need this")
        elif features["url_length"] > 75:
            score += 8
            timeline.append(f"🔍 URL length ({features['url_length']} chars) is above average")

        # IP address instead of domain
        if features["has_ip_address"]:
            score += 25
            timeline.append("⚠️ URL uses a raw IP address instead of a domain name — a classic phishing technique")

        # @ symbol
        if features["has_at_symbol"]:
            score += 20
            timeline.append("⚠️ URL contains '@' symbol — browsers ignore everything before '@', masking the real destination")

        # Suspicious TLD
        if features["suspicious_tld"]:
            score += 20
            timeline.append(f"⚠️ Domain uses '{features['tld']}' — a top-level domain associated with free/anonymous registrations")

        # Brand impersonation
        if features["brand_impersonation"]:
            brand = features["brand_impersonation"]["impersonates"]
            method = features["brand_impersonation"]["method"]
            score += 30
            timeline.append(f"🎭 Domain impersonates '{brand}' ({method.replace('_', ' ')}) — designed to fool you into trusting it")

        # Homoglyphs
        if features["homoglyphs"]:
            score += 25
            for h in features["homoglyphs"][:2]:
                timeline.append(f"🔡 Lookalike character detected: {h} — tricks your eye into reading a fake domain as real")

        # Many subdomains
        if features["subdomain_count"] > 3:
            score += 10
            timeline.append(f"🔍 {features['subdomain_count']} subdomains detected — attackers use deep nesting to hide the real domain")
        elif features["subdomain_count"] > 1:
            score += 5

        # High entropy (random-looking domain)
        if features["domain_entropy"] > 4.0:
            score += 15
            timeline.append(f"🎲 Domain has high randomness (entropy {features['domain_entropy']}) — likely auto-generated by attack infrastructure")

        # Redirect parameters
        if features["has_redirect_param"]:
            score += 10
            timeline.append("↩️ URL contains redirect parameter — may route you through a legitimate site before landing on a malicious one")

        # No HTTPS
        if not features["has_https"]:
            score += 10
            timeline.append("🔓 URL uses HTTP (not HTTPS) — your data would be transmitted unencrypted")
        
        # High digit ratio in domain
        if features["digit_ratio"] > 0.4:
            score += 10
            timeline.append(f"🔢 Domain is {int(features['digit_ratio']*100)}% digits — unusual for legitimate businesses")

        # Many hyphens
        if features["hyphen_count"] > 2:
            score += 8
            timeline.append(f"➖ Domain contains {features['hyphen_count']} hyphens — often used to create convincing fake domains")

    score = min(100, max(0, score))
    
    # Final verdict step
    if score >= 70:
        timeline.append("🛑 Conclusion: Multiple high-confidence phishing indicators detected — do not visit this URL")
    elif score >= 40:
        timeline.append("⚠️ Conclusion: Suspicious patterns detected — exercise extreme caution")
    else:
        timeline.append("✅ Conclusion: No major phishing indicators detected")
    
    return score, timeline


def get_explanation(score: int, features: dict) -> str:
    """Generate plain-English ELI5 explanation."""
    domain = features.get("domain", "this website")
    brand = features.get("brand_impersonation", {}).get("impersonates")
    
    if score >= 80:
        if brand:
            return f"This link pretends to be {brand.capitalize()} but is actually a fake website designed to steal your password or personal information. Do NOT click it — delete it immediately and report to IT."
        return "This link shows multiple signs of being a phishing trap. It was likely sent to steal your password, credit card, or personal information. Do NOT click it."
    elif score >= 60:
        if brand:
            return f"This link looks like it might be from {brand.capitalize()} but uses a suspicious domain. Before clicking, verify with your IT team or visit {brand}.com directly in a new tab."
        return "This link has suspicious characteristics. Do not enter any personal information if you visit it. When in doubt, contact IT support."
    elif score >= 35:
        return "This URL shows some unusual characteristics but no definitive phishing signs. Proceed with caution and do not enter passwords or payment information."
    else:
        return "This URL appears to be legitimate based on our analysis. Always stay vigilant — phishers continuously evolve their tactics."


def analyze_url(url: str) -> dict:
    """Main entry point for URL analysis."""
    url = url.strip()
    
    features = extract_features(url)
    score, timeline = score_url(features)
    explanation = get_explanation(score, features)
    
    # Verdict thresholds
    if score >= 65:
        verdict = "malicious"
    elif score >= 35:
        verdict = "suspicious"
    else:
        verdict = "safe"
    
    # Technical details for expandable section
    technical = {
        "parsed_domain": features["domain"],
        "tld": features["tld"],
        "uses_https": features["has_https"],
        "ip_address_used": bool(features["has_ip_address"]),
        "subdomain_count": features["subdomain_count"],
        "url_length": features["url_length"],
        "domain_entropy": features["domain_entropy"],
        "homoglyphs_detected": features["homoglyphs"],
        "brand_impersonation": features["brand_impersonation"],
        "suspicious_tld": bool(features["suspicious_tld"]),
        "redirect_parameters": bool(features["has_redirect_param"]),
    }
    
    # Clean features for response (remove non-serializable items)
    clean_features = {k: v for k, v in features.items() 
                     if isinstance(v, (int, float, str, bool, list)) and k not in ["domain", "path", "tld"]}
    
    
    return {
        "score": score,
        "verdict": verdict,
        "timeline": timeline,
        "explanation": explanation,
        "technical": technical,
        "features": clean_features,
    }

def extract_urls(text):
    """Extract URLs from a string using regex."""
    import re
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
    return re.findall(url_pattern, text)

def extract_urls(text):
    """Extract all URLs from a string using regex."""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?'
    return re.findall(url_pattern, text)

def analyze_url(url):
    """
    Analyze a URL and return a verdict.
    Returns a dict with: verdict (safe/malicious), score (0-100), explanation, timeline.
    """
    # Placeholder – replace with your actual ML or rule-based logic
    suspicious_indicators = []
    
    # Basic heuristics
    if len(url) > 75:
        suspicious_indicators.append("Unusually long URL")
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        suspicious_indicators.append("IP address used instead of domain name")
    
    # Check for brand impersonation (simplified)
    for brand in TOP_BRANDS:  # TOP_BRANDS should be defined earlier in the file
        if brand in url.lower() and not url.lower().startswith(f"https://{brand}"):
            suspicious_indicators.append(f"Impersonates {brand}")
            break
    
    score = min(len(suspicious_indicators) * 20, 100)  # 0-100 scale
    
    if score >= 60:
        verdict = "malicious"
        explanation = f"This link shows suspicious signs: {', '.join(suspicious_indicators)}. Do not click."
    else:
        verdict = "safe"
        explanation = "No obvious signs of phishing detected, but stay cautious."
    
    return {
        "verdict": verdict,
        "score": score,
        "explanation": explanation,
        "timeline": [f"⚠️ {indicator}" for indicator in suspicious_indicators] or ["✅ No immediate threats found"]
    }