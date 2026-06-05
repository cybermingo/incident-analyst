import math
import time
from collections import defaultdict
import re

VELOCITY_STORE = defaultdict(list)

ATTACK_MAPPING = {
    "bruteforce": ("T1110", "Brute Force", "High"),
    "rce": ("T1059", "Command Injection", "Critical"),
    "csrf": ("T1188", "Cross-Site Request Forgery", "Medium"),
    "lfi": ("T1006", "Local File Inclusion", "High"),
    "webshell": ("T1505.003", "File Upload (Web Shell)", "Critical"),
    "insecure_captcha": ("T1556", "Insecure CAPTCHA Bypass", "Low"),
    "sql_injection": ("T1190", "SQL Injection", "High"),
    "sqli_blind": ("T1190", "Blind SQL Injection", "High"),
    "weak_session": ("T1531", "Weak Session IDs", "Medium"),
    "xss": ("T1059.007", "Cross-site Scripting (XSS)", "Medium"),
    "csp_bypass": ("T1562.004", "CSP Bypass", "Medium"),
    "javascript_bypass": ("T1059.007", "JavaScript Bypass", "Low"),
}

def build_alert(atype, details, source=None):
    tid, name, sev = ATTACK_MAPPING.get(atype, ("T0000", "Unknown Anomaly", "Low"))
    return {
        "alert_type": atype,
        "severity": sev,
        "technique_id": tid,
        "technique_name": name,
        "details": details,
        "source": source
    }

def calculate_entropy(data_string: str) -> float:
    if not data_string: return 0.0
    entropy = 0
    for x in set(data_string):
        p_x = float(data_string.count(x)) / len(data_string)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def check_velocity(ip: str, endpoint: str, time_window: int = 5, limit: int = 4) -> bool:
    now = time.time()
    key = f"{ip}_{endpoint}"
    VELOCITY_STORE[key] = [t for t in VELOCITY_STORE[key] if now - t < time_window]
    VELOCITY_STORE[key].append(now)
    return len(VELOCITY_STORE[key]) > limit

def calculate_traversal_depth(path: str) -> int:
    return path.count("../") + path.count("..%2f") + path.count("..\\")

def get_operator_density(payload: str, operators: list) -> float:
    if not payload: return 0.0
    op_count = sum(payload.lower().count(op) for op in operators)
    return op_count / len(payload) if len(payload) > 0 else 0.0

def detect_bruteforce(e, p, q, ip):
    if "/vulnerabilities/brute/" in p and check_velocity(ip, "brute", time_window=3, limit=3):
        return build_alert("bruteforce", "High-velocity authentication probing detected.", ip)
    return None

def detect_rce(e, p, q, ip):
    if "/vulnerabilities/exec/" in p:
        if q and any(sep in q for sep in [";", "&&", "||", "|", "`", "$("]):
            return build_alert("rce", "Critical: OS Command Injection attempt detected.", ip)
    return None

def detect_lfi(e, p, q, ip):
    full_log = f"{p} {q}"
    has_traversal = "../" in q or "..%2f" in q or "..\\" in q
    has_sensitive_file = "etc/passwd" in q or "boot.ini" in q
    
    if has_traversal or has_sensitive_file:
        depth = calculate_traversal_depth(full_log)
        return build_alert("lfi", f"Directory traversal detected. Depth: {depth}", ip)
    return None

def detect_csrf(e, p, q, ip):
    if "/vulnerabilities/csrf/" in p and "password_new=" in q:
        referrer = e.get("referrer", "").lower()
        if "dvwa" not in referrer:
            return build_alert("csrf", "State-change requested without valid internal origin context.", ip)
    return None

def detect_webshell(e, p, q, ip):
    method = e.get("method", "")
    
    if "/vulnerabilities/upload" in p and method == "post":
        full_payload = (q + e.get("raw_request", "")).lower()
        
        if "%00" in full_payload or "\\x00" in full_payload:
            return build_alert("webshell", "CRITICAL: Null-byte injection evasion detected.", ip)
            
        bad_exts = [".php", ".phtml", ".phar", ".asp", ".aspx", ".jsp", ".sh", ".exe", ".cgi", ".py", ".pl"]
        if any(ext in full_payload for ext in bad_exts):
            return build_alert("webshell", "Code-execution file upload attempt detected.", ip)

    if "/hackable/uploads/" in p:
        file_name = p.split('/')[-1].lower()
        
        if not file_name: 
            return None
            
        if file_name.count('.') > 1:
            return build_alert("webshell", f"Evasion attempt: Multiple extensions detected in {file_name}", ip)
            
        safe_pattern = re.compile(r"^[a-z0-9_-]+\.(jpg|jpeg|png|gif|pdf)$")
        if not safe_pattern.match(file_name):
            return build_alert("webshell", f"ANOMALY: Unauthorized file type execution blocked: {file_name}", ip)
            
    return None

def detect_captcha_bypass(e, p, q, ip):
    if "/vulnerabilities/captcha/" in p and "step=2" in q.lower() and "g-recaptcha-response" not in q.lower():
        return build_alert("insecure_captcha", "Sequential logic bypass. Stage 2 accessed without Stage 1 validation.", ip)
    return None

def detect_sqli(e, p, q, ip):
    if not q: return None
    
    params = e.get("query_params", {})
    payloads = [str(val).lower() for sublist in params.values() for val in sublist] if params else [q]
    
    waf_regex = re.compile(r"(?i)(union\s+.*?select|sleep\s*\(|waitfor\s+delay|benchmark\s*\(|(?:'|\"|\b\d+\b)\s*(?:and|or)\s+.*?(=|>|<|like|true|false)|order\s+by\s+\d+)")

    for payload in payloads:
        if "/vulnerabilities/sqli_blind/" in p:
            if waf_regex.search(payload) or get_operator_density(payload, ["and", "or", "sleep"]) > 0.1 or check_velocity(ip, "sqli_blind", limit=4):
                return build_alert("sqli_blind", "Blind SQLi structural pattern or timing anomaly detected.", ip)
                
        if "/vulnerabilities/sqli/" in p:
            if waf_regex.search(payload) or get_operator_density(payload, ["union", "select", "'", "--"]) > 0.08:
                return build_alert("sql_injection", "SQL syntax anomaly or known SQLi signature detected.", ip)
                
    return None

def detect_weak_session(e, p, q, ip):
    if "/vulnerabilities/weak_id/" in p:
        return build_alert("weak_session", "Insecure session token generation accessed. Potential predictable cookie sequence.", ip)
    return None

def detect_xss(e, p, q, ip):
    if "/vulnerabilities/xss_s/" in p and e.get("method") == "post":
        return build_alert("xss", "Guestbook POST interaction detected. Potential Stored XSS payload dropped.", ip)
        
    if "/vulnerabilities/xss" in p and q:
        tag_density = get_operator_density(q, ["<", ">", "script", "img", "onerror"])
        entropy = calculate_entropy(q)
        
        if tag_density > 0.05 or entropy > 4.0:
            variant = "Reflected" if "xss_r" in p else "DOM"
            return build_alert("xss", f"{variant} payload heuristics met. Entropy: {entropy:.2f}, Density: {tag_density:.2f}", ip)
    return None

def detect_bypasses(e, p, q, ip):
    if "/vulnerabilities/csp/" in p:
        if "script" in (p + q) and "http" in (p + q):
            return build_alert("csp_bypass", "External script injection attempt.", ip)
            
    if "/vulnerabilities/javascript/" in p:
        return build_alert("javascript_bypass", "JavaScript validation endpoint accessed. Investigating potential bypass.", ip)
        
    return None

def run_all_detections(events):
    alerts = []
    for e in events:
        if e.get("event") != "web_request":
            continue
            
        p = e.get("path", "").lower()
        q = e.get("query_decoded", "").lower()
        ip = e.get("source_ip", "Unknown")
        
        checks = [
            detect_bruteforce, detect_rce, detect_csrf, detect_lfi, 
            detect_webshell, detect_captcha_bypass, detect_sqli, 
            detect_weak_session, detect_xss, detect_bypasses
        ]
        
        for check in checks:
            result = check(e, p, q, ip)
            if result:
                alerts.append(result)
                
    return alerts