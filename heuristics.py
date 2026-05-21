# heuristics.py

from urllib.parse import urlparse

# Suspicious gaming-related keywords
SUSPICIOUS_KEYWORDS = [
    "free gta",
    "minecraft hack",
    "robux generator",
    "steam free",
    "crack",
    "keygen",
    ".exe",
    ".scr",
    ".bat",
    "free nitro",
    "discord nitro",
    "cheat download",
    "aimbot",
    "wallhack"
]

# URL shorteners often hide malicious destinations
SHORT_DOMAINS = {
    'bit.ly',
    'tinyurl.com',
    't.co',
    'ow.ly',
    'goo.gl',
    'is.gd'
}


def is_short_link(url):

    try:
        host = urlparse(url).netloc.lower()

        return any(host.endswith(d) for d in SHORT_DOMAINS)

    except Exception:
        return False


def contains_suspicious_keywords(message_text):

    text = message_text.lower()

    return any(
        keyword in text
        for keyword in SUSPICIOUS_KEYWORDS
    )


def decision_engine_local(vt_report, message_text, gemini_report=None):

    positives = vt_report.get('positives', 0)

    reason = []

    heuristic_score = 0

    # -------------------------
    # VirusTotal logic
    # -------------------------

    if positives >= 3:
        heuristic_score += 3
        reason.append(f"Confirmed Malware ({positives} detections)")

    elif positives > 0:
        heuristic_score += 2
        reason.append(f"Suspicious Link ({positives} scanners flagged this)")

    # -------------------------
    # Heuristic keyword analysis
    # -------------------------

    if contains_suspicious_keywords(message_text):
        heuristic_score += 1
        reason.append("Suspicious gaming-related keywords detected")

    # -------------------------
    # Short link detection
    # -------------------------

    if is_short_link(message_text):
        heuristic_score += 1
        reason.append("Hidden/Shortened URL detected")

    # -------------------------
    # Gemini AI signal
    # -------------------------

    if gemini_report:

        risk = gemini_report.get("risk_level", "").lower()

        if risk == "high":
            heuristic_score += 2
            reason.append("Gemini AI classified as HIGH risk")

        elif risk == "medium":
            heuristic_score += 1
            reason.append("Gemini AI classified as MEDIUM risk")

    # -------------------------
    # Final decision
    # -------------------------

    if heuristic_score >= 3:
        action = "BLOCK"

    elif heuristic_score >= 1:
        action = "WARN"

    else:
        action = "ALLOW"
        reason.append("Clean")

    return {
        "action": action,
        "reason": ", ".join(reason),
        "vt": vt_report,
        "score": heuristic_score
    }