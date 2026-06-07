"""
Email Inspector - Parse and analyze email headers and body for phishing.
"""
import re
import email
from email import policy
from utils.url_analyzer import analyze_url

URGENCY_PHRASES = [
    ("immediately", "Urgency manipulation"),
    ("urgent", "Urgency manipulation"),
    ("verify your", "Credential harvesting request"),
    ("password expired", "Credential harvesting"),
    ("account suspended", "Fear tactic"),
    ("account will be", "Fear tactic"),
    ("click here", "Direct action request"),
    ("limited time", "Scarcity pressure"),
    ("act now", "Urgency manipulation"),
    ("confirm your", "Credential harvesting"),
    ("unusual sign", "Fear tactic"),
    ("unauthorized access", "Fear tactic"),
    ("your account", "Account targeting"),
    ("security alert", "Fear tactic"),
    ("final notice", "Urgency escalation"),
    ("gift card", "Payment diversion"),
    ("wire transfer", "Payment fraud"),
    ("invoice attached", "Malware delivery"),
    ("delivery failed", "Package scam"),
    ("you have won", "Prize scam"),
]

AUTHORITY_INDICATORS = [
    "ceo", "president", "director", "manager", "hr department",
    "it department", "it support", "finance team", "payroll",
    "microsoft support", "google security", "apple id",
    "internal audit", "compliance team",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r'no[-_]?reply@(?!.*\.(com|org|gov|edu)$)',
    r'support@\w+\.(tk|ml|ga|cf|gq|xyz)',
    r'security@(?!.*google|microsoft|apple)',
]


def parse_headers(eml_text: str) -> dict:
    """Extract and analyze email headers."""
    headers = {}
    try:
        msg = email.message_from_string(eml_text, policy=policy.default)
        headers = {
            "from": str(msg.get("From", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "spf": str(msg.get("Received-SPF", "Not present")),
            "dkim": str(msg.get("DKIM-Signature", "Not present")),
            "dmarc": str(msg.get("Authentication-Results", "Not present")),
            "x_mailer": str(msg.get("X-Mailer", "")),
        }
    except Exception:
        # Fallback: simple regex parsing
        from_match = re.search(r'^From:\s*(.+)$', eml_text, re.MULTILINE | re.IGNORECASE)
        subject_match = re.search(r'^Subject:\s*(.+)$', eml_text, re.MULTILINE | re.IGNORECASE)
        headers = {
            "from": from_match.group(1).strip() if from_match else "Unknown",
            "subject": subject_match.group(1).strip() if subject_match else "Unknown",
            "spf": "Not present",
            "dkim": "Not present",
            "dmarc": "Not present",
        }
    return headers


def analyze_spf_dkim_dmarc(headers: dict) -> dict:
    """Evaluate email authentication results."""
    spf = headers.get("spf", "").lower()
    dkim = headers.get("dkim", "").lower()
    dmarc = headers.get("dmarc", "").lower()
    
    results = {
        "spf": {
            "present": "not present" not in spf,
            "pass": "pass" in spf,
            "status": "pass" if "pass" in spf else ("fail" if "fail" in spf else "missing"),
        },
        "dkim": {
            "present": "not present" not in dkim and len(dkim) > 20,
            "status": "present" if len(dkim) > 20 else "missing",
        },
        "dmarc": {
            "present": "not present" not in dmarc,
            "pass": "pass" in dmarc,
            "status": "pass" if "pass" in dmarc else ("fail" if "fail" in dmarc else "missing"),
        },
    }
    
    # Overall auth score
    auth_score = 0
    if results["spf"]["pass"]:
        auth_score += 33
    if results["dkim"]["present"]:
        auth_score += 33
    if results["dmarc"]["pass"]:
        auth_score += 34
    
    results["auth_score"] = auth_score
    results["verdict"] = "strong" if auth_score >= 66 else ("weak" if auth_score >= 33 else "none")
    
    return results


def extract_urls(text: str) -> list[str]:
    """Extract all URLs from email body."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    # Clean up trailing punctuation
    cleaned = [re.sub(r'[.,;:!?\)>]+$', '', url) for url in urls]
    return list(set(cleaned))[:10]  # Limit to 10 URLs


def detect_urgency_phrases(text: str) -> list[dict]:
    """Detect urgency and manipulation phrases in email body."""
    text_lower = text.lower()
    found = []
    for phrase, tactic in URGENCY_PHRASES:
        if phrase in text_lower:
            # Find the surrounding context
            idx = text_lower.find(phrase)
            context_start = max(0, idx - 30)
            context_end = min(len(text), idx + len(phrase) + 30)
            context = text[context_start:context_end].strip()
            found.append({
                "phrase": phrase,
                "tactic": tactic,
                "context": f"...{context}...",
            })
    return found


def detect_authority_impersonation(headers: dict, body: str) -> list[str]:
    """Check for authority/role impersonation."""
    text = f"{headers.get('from', '')} {headers.get('subject', '')} {body}".lower()
    found = []
    for authority in AUTHORITY_INDICATORS:
        if authority in text:
            found.append(authority.title())
    return list(set(found))


def check_sender_mismatch(headers: dict) -> dict:
    """Check for From/Reply-To mismatch — classic phishing indicator."""
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply_to", "")
    
    from_domain = re.search(r'@([\w.-]+)', from_addr)
    reply_domain = re.search(r'@([\w.-]+)', reply_to)
    
    mismatch = False
    if from_domain and reply_domain:
        if from_domain.group(1).lower() != reply_domain.group(1).lower():
            mismatch = True
    
    return {
        "mismatch": mismatch,
        "from_domain": from_domain.group(1) if from_domain else None,
        "reply_to_domain": reply_domain.group(1) if reply_domain else None,
    }


def calculate_risk(urgency_phrases, auth_results, url_results, authority_impersonation, sender_mismatch) -> tuple[int, str, str]:
    """Calculate overall email risk score."""
    score = 0
    
    # Authentication failures
    if auth_results["auth_score"] < 33:
        score += 25
    elif auth_results["auth_score"] < 66:
        score += 10
    
    # Urgency/manipulation phrases
    score += min(30, len(urgency_phrases) * 8)
    
    # Authority impersonation
    score += min(20, len(authority_impersonation) * 10)
    
    # Sender mismatch
    if sender_mismatch["mismatch"]:
        score += 20
    
    # Malicious URLs found
    malicious_urls = [u for u in url_results if u.get("verdict") == "malicious"]
    suspicious_urls = [u for u in url_results if u.get("verdict") == "suspicious"]
    score += len(malicious_urls) * 25
    score += len(suspicious_urls) * 10
    
    score = min(100, score)
    
    if score >= 65:
        verdict = "malicious"
        action = "Delete this email immediately and report it to your IT security team. Do not click any links or open attachments."
    elif score >= 35:
        verdict = "suspicious"
        action = "Treat this email with extreme caution. Verify the sender through a separate channel before taking any action."
    else:
        verdict = "safe"
        action = "No immediate action required, but always verify unexpected requests through official channels."
    
    return score, verdict, action


def analyze_email(eml_text: str) -> dict:
    """Main entry point for email analysis."""
    headers = parse_headers(eml_text)
    
    # Get body text (everything after double newline)
    body_match = re.split(r'\n\n', eml_text, 1)
    body = body_match[1] if len(body_match) > 1 else eml_text
    
    auth_results = analyze_spf_dkim_dmarc(headers)
    urgency_phrases = detect_urgency_phrases(body)
    authority_impersonation = detect_authority_impersonation(headers, body)
    sender_mismatch = check_sender_mismatch(headers)
    
    # Extract and scan all URLs
    urls = extract_urls(body + " " + headers.get("from", ""))
    url_results = []
    for url in urls[:5]:  # Limit to 5 to keep response fast
        try:
            url_scan = analyze_url(url)
            url_results.append({
                "url": url,
                "score": url_scan["score"],
                "verdict": url_scan["verdict"],
                "explanation": url_scan["explanation"],
            })
        except Exception:
            url_results.append({"url": url, "score": 50, "verdict": "unknown", "explanation": "Could not analyze"})
    
    score, verdict, action = calculate_risk(
        urgency_phrases, auth_results, url_results, authority_impersonation, sender_mismatch
    )
    
    return {
        "score": score,
        "verdict": verdict,
        "recommended_action": action,
        "headers": {
            "from": headers.get("from"),
            "subject": headers.get("subject"),
            "date": headers.get("date"),
        },
        "authentication": auth_results,
        "urgency_phrases_detected": urgency_phrases,
        "authority_impersonation": authority_impersonation,
        "sender_mismatch": sender_mismatch,
        "urls_found": url_results,
        "summary": f"Found {len(urgency_phrases)} manipulation tactics, {len(authority_impersonation)} impersonation attempts, and {len([u for u in url_results if u['verdict'] in ['malicious','suspicious']])} suspicious URLs.",
    }
