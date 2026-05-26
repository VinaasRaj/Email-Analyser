import streamlit as st
import re
import requests

st.set_page_config(page_title="Ultimate Email Analyzer", layout="wide")

st.title("🛡️ Ultimate Email Security Analyzer")
st.write("Full SOC-level email triage tool")

headers = st.text_area("Paste Full Email Headers", height=300)
vt_api = st.text_input("VirusTotal API Key")
abuse_api = st.text_input("AbuseIPDB API Key")

# ===== FUNCTIONS =====

def extract_ips(text):
    return list(set(re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", text)))

def extract_urls(text):
    return re.findall(r"https?://[^\s]+", text)

def extract_hops(headers):
    hops = []
    lines = [l for l in headers.split("\n") if l.lower().startswith("received:")]
    for l in lines:
        hop = {}
        f = re.search(r'from\s+([^\s]+)', l)
        b = re.search(r'by\s+([^\s]+)', l)
        ip = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', l)
        if f: hop['from'] = f.group(1)
        if b: hop['by'] = b.group(1)
        if ip: hop['ip'] = ip.group(1)
        hops.append(hop)
    return hops

# Threat APIs

def check_ip(ip, api):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': api, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        return requests.get(url, headers=headers, params=params).json()
    except:
        return "Error"

# ===== ANALYSIS =====

if st.button("Analyze"):

    score = 0
    findings = []

    text = headers.lower()

    # SPF / DKIM / DMARC
    if "spf=pass" in text:
        findings.append("✅ SPF Passed")
    else:
        findings.append("❌ SPF Failed")
        score += 2

    if "dkim=pass" in text:
        findings.append("✅ DKIM Passed")
    else:
        findings.append("❌ DKIM Failed")
        score += 2

    if "dmarc=pass" in text:
        findings.append("✅ DMARC Passed")
    else:
        findings.append("❌ DMARC Failed")
        score += 3

    # Extract
    ips = extract_ips(headers)
    urls = extract_urls(headers)
    hops = extract_hops(headers)

    # Domain check
    from_domain = re.search(r'from:.*@([^\s>]+)', text)
    return_path = re.search(r'return-path:.*@([^\s>]+)', text)

    if from_domain and return_path and from_domain.group(1) != return_path.group(1):
        findings.append("⚠️ Domain mismatch (spoofing)")
        score += 3

    # Spam keywords
    spam_words = ["urgent", "verify", "password", "bank", "click"]
    for w in spam_words:
        if w in text:
            findings.append(f"⚠️ Spam indicator: {w}")
            score += 1

    # ===== OUTPUT =====

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Authentication Results")
        for f in findings:
            st.write(f)

        st.subheader("IP Addresses")
        st.write(ips)

        st.subheader("URLs")
        st.write(urls)

    with col2:
        st.subheader("Email Hops")
        for i, h in enumerate(hops):
            st.write(f"Hop {i+1}")
            st.json(h)

        st.subheader("Risk Score")
        st.write(score)

        if score >= 6:
            st.error("HIGH RISK")
        elif score >= 3:
            st.warning("SUSPICIOUS")
        else:
            st.success("LEGITIMATE")

    # Threat Intel
    if abuse_api and ips:
        st.subheader("AbuseIPDB Results")
        for ip in ips:
            st.json(check_ip(ip, abuse_api))

    # REPORT
    report = f"""Score: {score}
Findings: {findings}
IPs: {ips}
URLs: {urls}
"""

    st.download_button("Download Report", report, file_name="report.txt")
