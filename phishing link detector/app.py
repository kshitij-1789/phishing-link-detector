import os
import re
import urllib.parse
import requests
import base64  # Added for correct VirusTotal URL ID encoding
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# Replace with your actual VirusTotal API Key
VT_API_KEY = "04faf1d000ca318c186b7a28d4b2b7540efc18116826dd74578d135b3d078baf"
VT_API_URL = "https://www.virustotal.com/api/v3/urls"

def analyze_url_heuristics(url):
    """
    Analyzes a URL locally for common phishing indicators.
    Returns a list of reasons and a local suspension penalty score.
    """
    reasons = []
    local_score = 0
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
    except Exception:
        return ["Invalid URL structure"], 100

    # 1. Check URL Length
    if len(url) > 75:
        reasons.append("URL length is unusually long (> 75 chars).")
        local_score += 20

    # 2. Check for IP Address instead of Domain
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        reasons.append("URL uses an IP address instead of a domain name.")
        local_score += 40

    # 3. Check for suspicious symbols/characters
    if "@" in url:
        reasons.append("URL contains an '@' symbol (used to obfuscate real destination).")
        local_score += 30
    if domain.count('-') > 2:
        reasons.append("Excessive hyphens in the domain name.")
        local_score += 15

    # 4. Check for suspicious keywords in domain or path
    phishing_keywords = ['login', 'verify', 'bank', 'secure', 'update', 'signin', 'paypal', 'wallet', 'free', 'bonus']
    found_keywords = [kw for kw in phishing_keywords if kw in url.lower()]
    if found_keywords:
        reasons.append(f"Contains high-risk keywords: {', '.join(found_keywords)}")
        local_score += len(found_keywords) * 15

    # 5. Check for unusual/suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.country', '.stream', '.gq', '.tk', '.fit', '.cf', '.info']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        reasons.append("Uses a high-risk Top-Level Domain (TLD) commonly linked to phishing.")
        local_score += 25

    return reasons, min(local_score, 100)

def fetch_virustotal_report(url):
    """
    Cleans the URL, hashes it to a base64 ID, and fetches the analysis results 
    instantly from VirusTotal history to bypass wait queues.
    """
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return {"error": "API Key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # Clean the URL to ensure matching string generation
        cleaned_url = url.strip().rstrip('/')
        
        # VirusTotal API v3 requires URL identifiers to be base64 encoded strings without '=' padding
        url_bytes = cleaned_url.encode('utf-8')
        base64_bytes = base64.urlsafe_b64encode(url_bytes)
        url_id = base64_bytes.decode('utf-8').rstrip('=')
        
        # Look up existing historical database report directly
        get_report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(get_report_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return stats
            
        elif response.status_code == 404:
            # Fallback if the URL has genuinely never been looked up by VT before
            submit_response = requests.post(VT_API_URL, data={"url": cleaned_url}, headers=headers, timeout=10)
            if submit_response.status_code != 200:
                return {"error": f"VT Submission Failed: {submit_response.status_code}"}
            
            analysis_id = submit_response.json()['data']['id']
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(analysis_url, headers=headers, timeout=10)
            
            if report_response.status_code == 200:
                return report_response.json()['data']['attributes']['stats']
                
        return {"error": f"VT API Error: Status {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error connecting to VirusTotal: {str(e)}"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()

    # Basic URL validation
    if not url or not (url.startswith('http://') or url.startswith('https://')):
        return jsonify({"error": "Please provide a valid URL starting with http:// or https://"}), 400

    # 1. Run local heuristics
    heuristic_reasons, local_score = analyze_url_heuristics(url)

    # 2. Run VirusTotal Scan
    vt_stats = fetch_virustotal_report(url)
    
    if "error" in vt_stats:
        malicious = 0
        suspicious = 0
        harmless = 0
        vt_failed = True
        heuristic_reasons.append(f"VirusTotal Notice: {vt_stats['error']}. Fallback to heuristic scoring.")
    else:
        malicious = vt_stats.get('malicious', 0)
        suspicious = vt_stats.get('suspicious', 0)
        harmless = vt_stats.get('harmless', 0)
        vt_failed = False

    # 3. Calculate Hybrid Risk Score (0-100)
    vt_weight = (malicious * 40) + (suspicious * 15)
    risk_score = min(max(local_score, vt_weight), 100)

    # 4. Determine Verdict
    if risk_score >= 65 or malicious >= 2:
        verdict = "Phishing"
        verdict_color = "#ef4444" # Red
    elif risk_score >= 30 or malicious == 1 or suspicious > 0:
        verdict = "Suspicious"
        verdict_color = "#f59e0b" # Orange
    else:
        verdict = "Safe"
        verdict_color = "#10b981" # Green

    # 5. Generate Dynamic Recommendations
    recommendations = ["Do not reuse passwords across multiple sensitive sites."]
    if verdict == "Phishing":
        recommendations.insert(0, "DO NOT enter personal credentials or financial details on this webpage.")
        recommendations.insert(1, "Close the tab immediately and report this link to your organization's IT security.")
    elif verdict == "Suspicious":
        recommendations.insert(0, "Exercise extreme caution. Double-check the domain spelling closely.")
        recommendations.insert(1, "Verify the sender identity if you received this link via email/SMS.")
    else:
        recommendations.insert(0, "While flagged safe, always ensure proper HTTPS encryption is active before interacting.")

    # Standardize data payload return keys to perfectly map to front-end dashboard layout elements
    return jsonify({
        "url": url,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "risk_score": risk_score,
        "vt_malicious": malicious,
        "vt_suspicious": suspicious,
        "vt_harmless": harmless,
        "reasons": heuristic_reasons if heuristic_reasons else ["No apparent structural phishing anomalies detected."],
        "recommendations": recommendations,
        "vt_fallback": vt_failed
    })

if __name__ == '__main__':
    app.run(debug=True)