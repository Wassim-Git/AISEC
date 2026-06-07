"""
ChatCheck - Detect social engineering in Slack/Teams messages.
"""
import re
from utils.url_analyzer import analyze_url, extract_urls

IMPERSONATION_ROLES = {
    "CEO": ["ceo", "chief executive", "founder", "president"],
    "HR": ["hr", "human resources", "hr department", "hr team", "people team"],
    "IT Support": ["it support", "it department", "tech support", "helpdesk", "help desk", "sysadmin"],
    "Finance": ["finance", "accounting", "cfo", "chief financial", "accounts payable", "payroll"],
    "Legal": ["legal", "compliance", "counsel", "attorney"],
    "Security": ["security team", "infosec", "cyber", "security alert"],
}

SOCIAL_ENGINEERING_TACTICS = [
    ("gift card", "Payment diversion", 35),
    ("wire transfer", "Payment fraud", 35),
    ("bitcoin", "Cryptocurrency fraud", 30),
    ("itunes", "Gift card scam", 30),
    ("amazon gift", "Gift card scam", 30),
    ("click here", "Phishing link", 20),
    ("click the link", "Phishing link", 20),
    ("verify your", "Credential theft", 25),
    ("update your password", "Credential theft", 25),
    ("share your", "Data exfiltration", 20),
    ("send me", "Data exfiltration", 15),
    ("keep this confidential", "Secrecy request", 20),
    ("don't tell", "Secrecy request", 20),
    ("between us", "Secrecy request", 15),
    ("immediately", "Urgency pressure", 10),
    ("right now", "Urgency pressure", 10),
    ("urgent", "Urgency pressure", 15),
    ("asap", "Urgency pressure", 10),
    ("unusual activity", "Fear tactic", 15),
    ("suspended", "Fear tactic", 20),
    ("direct message", "Channel bypass", 10),
    ("personal email", "Channel bypass", 15),
]

SAFE_VERSION_TEMPLATES = {
    "payment": "Real {role} would never request payments, gift cards, or wire transfers via chat. If you receive such a request, call {role} directly using a number from your company directory — never from this message.",
    "credentials": "Real {role} will never ask for your password, PIN, or authentication codes through chat. If you receive such a request, report it to IT Security immediately.",
    "link": "Before clicking any link from {role} in chat, verify it by hovering over the URL and checking it matches your company's official domain. When in doubt, navigate directly to the service.",
    "generic": "Real {role} communications about sensitive actions happen through official channels with proper verification. If in doubt, verify through a separate communication channel.",
    "secrecy": "Any legitimate request will not ask you to keep it secret from colleagues. This is a major red flag for social engineering. Report this conversation to your manager and IT security.",
}


def detect_impersonation(message: str) -> list[dict]:
    """Detect which roles are being impersonated."""
    msg_lower = message.lower()
    found = []
    
    for role, keywords in IMPERSONATION_ROLES.items():
        for keyword in keywords:
            if keyword in msg_lower:
                # Check if it's a direct reference (not just mentioned)
                # Pattern: "From HR:", "HR here:", "IT Support:", etc.
                if re.search(rf'\b{re.escape(keyword)}[\s:,]', msg_lower):
                    found.append({
                        "role": role,
                        "keyword_matched": keyword,
                        "severity": "high" if role in ["CEO", "IT Support", "Finance"] else "medium",
                    })
                    break
    
    return found


def detect_tactics(message: str) -> list[dict]:
    """Detect specific social engineering tactics."""
    msg_lower = message.lower()
    found = []
    
    for phrase, tactic, weight in SOCIAL_ENGINEERING_TACTICS:
        if phrase in msg_lower:
            idx = msg_lower.find(phrase)
            context_start = max(0, idx - 20)
            context_end = min(len(message), idx + len(phrase) + 20)
            found.append({
                "phrase": phrase,
                "tactic": tactic,
                "weight": weight,
                "context": f"...{message[context_start:context_end]}...",
            })
    
    return found


def generate_safe_version(message: str, impersonation: list, tactics: list, urls: list) -> str:
    """Generate recommended safe response for the user."""
    role = impersonation[0]["role"] if impersonation else "this sender"
    
    # Determine what template to use
    has_payment = any(t["tactic"] in ["Payment diversion", "Payment fraud", "Gift card scam", "Cryptocurrency fraud"] for t in tactics)
    has_credentials = any(t["tactic"] in ["Credential theft"] for t in tactics)
    has_secrecy = any(t["tactic"] in ["Secrecy request"] for t in tactics)
    has_links = len(urls) > 0
    
    if has_secrecy:
        template = SAFE_VERSION_TEMPLATES["secrecy"]
    elif has_payment:
        template = SAFE_VERSION_TEMPLATES["payment"]
    elif has_credentials:
        template = SAFE_VERSION_TEMPLATES["credentials"]
    elif has_links:
        template = SAFE_VERSION_TEMPLATES["link"]
    else:
        template = SAFE_VERSION_TEMPLATES["generic"]
    
    return template.format(role=role)


def calculate_chat_risk(impersonation, tactics, url_results) -> tuple[int, str]:
    """Calculate risk score for chat message."""
    score = 0
    
    # Impersonation
    for imp in impersonation:
        score += 25 if imp["severity"] == "high" else 15
    
    # Tactics
    for tactic in tactics:
        score += tactic["weight"]
    
    # Malicious URLs
    for url in url_results:
        if url.get("verdict") == "malicious":
            score += 30
        elif url.get("verdict") == "suspicious":
            score += 15
    
    score = min(100, score)
    
    if score >= 65:
        verdict = "high_risk"
    elif score >= 35:
        verdict = "suspicious"
    else:
        verdict = "low_risk"
    
    return score, verdict


def analyze_chat(message: str, platform: str = "unknown") -> dict:
    """Main entry point for chat message analysis."""
    impersonation = detect_impersonation(message)
    tactics = detect_tactics(message)
    
    # Extract and scan URLs
    urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', message)
    url_results = []
    for url in urls[:3]:
        try:
            scan = analyze_url(url.strip())
            url_results.append({
                "url": url,
                "score": scan["score"],
                "verdict": scan["verdict"],
            })
        except Exception:
            pass
    
    score, verdict = calculate_chat_risk(impersonation, tactics, url_results)
    safe_version = generate_safe_version(message, impersonation, tactics, url_results)
    
    # Risk flags
    flags = []
    if impersonation:
        roles = ", ".join(i["role"] for i in impersonation)
        flags.append(f"🎭 Impersonates internal role: {roles}")
    if any(t["tactic"] in ["Payment diversion", "Payment fraud", "Gift card scam"] for t in tactics):
        flags.append("💸 Requests financial action (gift cards / wire transfer)")
    if any(t["tactic"] in ["Credential theft"] for t in tactics):
        flags.append("🔑 Attempts to steal credentials")
    if any(t["tactic"] in ["Urgency pressure"] for t in tactics):
        flags.append("⏰ Uses urgency pressure tactics")
    if any(t["tactic"] in ["Secrecy request"] for t in tactics):
        flags.append("🤫 Requests confidentiality — major social engineering red flag")
    if url_results:
        dangerous = [u for u in url_results if u["verdict"] in ["malicious", "suspicious"]]
        if dangerous:
            flags.append(f"🔗 Contains {len(dangerous)} suspicious/malicious link(s)")
    
    # Explanation
    if score >= 65:
        explanation = f"This message shows strong signs of a social engineering attack. {'It impersonates ' + impersonation[0]['role'] + ' to gain your trust. ' if impersonation else ''}Ignore this message and report it to your security team."
    elif score >= 35:
        explanation = "This message shows suspicious patterns. Verify the sender's identity through a separate channel before taking any action."
    else:
        explanation = "This message appears normal, but always verify sensitive requests through official channels."
    
    return {
        "score": score,
        "verdict": verdict,
        "flags": flags,
        "explanation": explanation,
        "safe_version": safe_version,
        "impersonation_detected": impersonation,
        "tactics_detected": tactics,
        "urls_scanned": url_results,
        "platform": platform,
        "summary": f"Detected {len(impersonation)} impersonation attempts, {len(tactics)} manipulation tactics, and {len(url_results)} URLs.",
    }
