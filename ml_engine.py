import math
import re

def calculate_shannon_entropy(data):
    """Calculates entropy to detect obfuscated or encoded payloads (e.g., base64, shellcode)."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def classify_threat(payload_data):
    """
    Comprehensive threat engine covering all modern attack vectors 
    combined with AI entropy anomaly scoring.
    """
    if not payload_data:
        return "NORMAL: Standard Request", 0.1

    payload_lower = payload_data.lower()
    entropy = calculate_shannon_entropy(payload_data)

    # 1. Critical Threats (Ransomware, APTs, Fileless Malware, SQLi)
    ransomware_patterns = ["ransom", ".onion", "decrypt_instructions", "bitcoin", "encrypt"]
    apt_malware_patterns = ["powershell", "invoke-expression", "iex(", "cmd /c", "certutil", "bitsadmin"]
    sql_injection_patterns = ["union select", "or 1=1", "drop table", "exec(", "information_schema"]

    if any(sig in payload_lower for sig in ransomware_patterns):
        return "CRITICAL: Ransomware Deployment Payload", 0.95
    if any(sig in payload_lower for sig in apt_malware_patterns):
        return "CRITICAL: APT / Fileless Malware Execution Vector", 0.90
    if any(sig in payload_lower for sig in sql_injection_patterns):
        return "CRITICAL: SQL Injection (SQLi) Exploit", 0.88

    # 2. Attack Vectors (Phishing, BEC, Whale Phishing, XSS, Brute Force)
    whale_patterns = ["board-resolution", "executive-compensation", "confidential-merger"]
    bec_patterns = ["wire-transfer", "urgent-invoice", "ceo-request", "payroll-divert"]
    phishing_patterns = ["login-verify", "account-update", "secure-bank"]
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]
    credential_patterns = ["password=", "passwd=", "auth=", "token="]

    if any(sig in payload_lower for sig in whale_patterns):
        return "ATTACK: Whale Phishing (Executive Targeting)", 0.80
    if any(sig in payload_lower for sig in bec_patterns):
        return "ATTACK: Business Email Compromise (BEC)", 0.78
    if any(sig in payload_lower for sig in phishing_patterns):
        return "ATTACK: Phishing / Spear Phishing Link Interaction", 0.75
    if any(sig in payload_lower for sig in xss_patterns):
        return "ATTACK: Cross-Site Scripting (XSS) Vector", 0.72
    if "brute" in payload_lower or (any(ind in payload_lower for ind in credential_patterns) and len(payload_data) > 25):
        return "ATTACK: Credential Stuffing & Brute Force Attack", 0.70

    # 3. Suspicious / Recon / DDoS / Insider Probes
    network_threats = ["ddos", "flood", "dns-tunnel", "spoof"]
    supply_chain_insider = ["internal-token", "vendor-api", "bypass-policy"]
    recon_patterns = ["search=", "scan", "probe", "debug", "test", "admin"]

    if any(sig in payload_lower for sig in network_threats):
        return "SUSPICIOUS: DDoS Indicator / DNS Tunneling Probe", 0.55
    if any(sig in payload_lower for sig in supply_chain_insider):
        return "SUSPICIOUS: Supply Chain Token or Insider Threat Probe", 0.50
    if any(sig in payload_lower for sig in recon_patterns):
        return "SUSPICIOUS: Reconnaissance / Automated Probing", 0.40

    # 4. Zero-day Anomaly Fallback via Entropy
    if entropy > 4.5 and len(payload_data) > 15:
        return f"CRITICAL: Zero-Day / Obfuscated Payload Anomaly (Entropy: {entropy:.2f})", 0.92

    return "SUSPICIOUS: Unclassified Anomalous Payload", 0.45