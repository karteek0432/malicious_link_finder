import customtkinter as ctk
import requests
import threading
import time
import re
import os
from urllib.parse import urlparse
import tldextract
from PIL import Image

# === CONFIGURATION ===
API_KEY = os.getenv("API_KEY") 


EDUCATIONAL_DOMAINS = {
    "testphp.vulnweb.com", "demo.testfire.net", "www.xsslabelgg.com",
    "dvwa.local", "bodgeit.appspot.com", "juiceshop.org", "hack.me", "mutillidae"
}

SUSPICIOUS_DOMAINS = {
    "serveo.net", "ngrok.io", "localhost.run",
    "localtunnel.github.io", "vps.free/in"
}

MANUAL_BLACKLIST = {
    "gmail-review-activity.com",
    "icloud-verify-login.net",
    "dropbox-document-request.com"
}

SCAN_INTERVAL = 15
last_scan_time = [0]

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

app = ctk.CTk()
app.title("Malicious Website Finder")
app.geometry("600x450")

# === UTILITY FUNCTIONS ===
def normalize_url(url):
    url = url.strip()
    if not urlparse(url).scheme:
        return "https://" + url.lstrip("http://").lstrip("https://")
    return url

def is_valid_url(url):
    regex = re.compile(r'^https?://(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def make_api_request(url, headers=None, data=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            if data:
                resp = requests.post(url, headers=headers, data=data, timeout=10, verify=True)
            else:
                resp = requests.get(url, headers=headers, timeout=10, verify=True)
            if resp.status_code == 429:
                time.sleep(int(resp.headers.get("Retry-After", "5")))
                continue
            return resp
        except requests.RequestException:
            time.sleep(2)
    return None

def get_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}".lower()

def is_suspicious_domain(url):
    domain = get_domain(url)
    return any(domain.endswith(sd) for sd in SUSPICIOUS_DOMAINS)

def is_educational_site(url):
    domain = get_domain(url)
    return domain in EDUCATIONAL_DOMAINS

def is_blacklisted(url):
    domain = get_domain(url)
    return domain in MANUAL_BLACKLIST

def heuristic_check(url):
    if "@" in url.split("//")[-1]:
        return "URL contains '@' — often used in phishing."
    match = re.search(r"//([a-zA-Z0-9.-]+)", url)
    if match and len(match.group(1)) > 30:
        return "Very long subdomain detected — possible phishing."
    keywords = ["verify", "login", "admin", "free", "account", "signin", "hack", "security", "review", "activity", "update", "password", "support", "dropbox", "document", "share", "access"]
    if any(kw in url.lower() for kw in keywords):
        return f"Phishing keyword detected in URL: '{url}'"
    return None

def check_phishtank(url):
    try:
        response = requests.post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format": "json"}, headers={"User-Agent": "PhishTank-Checker"}, timeout=10, verify=True)
        if response.status_code == 200:
            json_data = response.json()
            return json_data.get("results", {}).get("valid", False) and json_data.get("results", {}).get("verified", False)
        return False
    except:
        return False

def check_url_simple(url, api_key, result_callback):
    try:
        progress_bar.set(0.1)
        now = time.time()
        if now - last_scan_time[0] < SCAN_INTERVAL:
            result_callback(f"Please wait {int(SCAN_INTERVAL - (now - last_scan_time[0]))}s before next scan.", "default")
            progress_bar.set(1.0)
            return
        last_scan_time[0] = now

        if is_educational_site(url):
            result_callback("📘 Educational/Test Site\nFor security training purposes.", "educational")
            progress_bar.set(1.0)
            return

        heuristic_msg = heuristic_check(url)
        if heuristic_msg:
            result_callback(heuristic_msg, "malicious")
            progress_bar.set(1.0)
            return

        if is_blacklisted(url):
            result_callback("🚨 BLACKLISTED DOMAIN DETECTED", "malicious")
            progress_bar.set(1.0)
            return

        progress_bar.set(0.3)
        if check_phishtank(url):
            result_callback("🛑 PHISHTANK VERIFIED PHISHING SITE", "malicious")
            progress_bar.set(1.0)
            return

        progress_bar.set(0.5)
        headers = {"x-apikey": api_key}
        submit_resp = make_api_request("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if not submit_resp or submit_resp.status_code != 200:
            result_callback("[ERROR] Could not submit URL.", "default")
            progress_bar.set(1.0)
            return

        scan_id = submit_resp.json().get("data", {}).get("id")
        if not scan_id:
            result_callback("[ERROR] Invalid API response.", "default")
            progress_bar.set(1.0)
            return

        progress_bar.set(0.7)
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        for i in range(15):
            report_resp = make_api_request(report_url, headers=headers)
            if report_resp and report_resp.status_code == 200:
                report_data = report_resp.json()
                if report_data["data"]["attributes"]["status"] == "completed":
                    stats = report_data["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    if malicious > 0:
                        result_callback(f"🚨 MALICIOUS ({malicious} detections)", "malicious")
                    elif suspicious > 0:
                        result_callback(f"⚠️ SUSPICIOUS ({suspicious} flags)", "malicious")
                    else:
                        result_callback("✅ This website is safe.", "safe")
                    progress_bar.set(1.0)
                    return
            time.sleep(1)
            progress_bar.set(0.7 + (i+1)*0.02)

        result_callback("[ERROR] Scan timed out.", "default")
        progress_bar.set(1.0)
    except Exception as e:
        result_callback(f"[EXCEPTION] {str(e)}", "default")
        progress_bar.set(1.0)

def start_scan():
    raw_url = url_entry.get().strip()
    if not raw_url:
        result_box.configure(text="Please enter a URL.", text_color="yellow")
        return
    url = normalize_url(raw_url)
    if re.search(r"^[^@]*:[^@]*@", url):
        result_box.configure(text="⚠️ Blocked! URL contains credentials.", text_color="red")
        return
    if not is_valid_url(url):
        result_box.configure(text="Invalid URL format!", text_color="red")
        return
    if is_suspicious_domain(url):
        result_box.configure(text="⚠️ Suspicious tunneling domain detected!", text_color="orange")
        return

    result_box.configure(text="🔍 Scanning...", text_color="lime", font=("Consolas", 16, "bold"))
    progress_bar.set(0)

    def callback(text, style):
        color = {"malicious": "red", "safe": "lime", "educational": "#00BFFF"}.get(style, "yellow")
        result_box.configure(text=text, text_color=color, font=("Impact", 26, "bold"))

    threading.Thread(target=check_url_simple, args=(url, API_KEY, callback), daemon=True).start()

# === THEME STATE ===
theme_state = {"dark": True}
def toggle_theme():
    if theme_state["dark"]:
        ctk.set_appearance_mode("light")
    else:
        ctk.set_appearance_mode("dark")
    theme_state["dark"] = not theme_state["dark"]

# === GUI ===
title_label = ctk.CTkLabel(app, text="Malicious Website Finder", font=("Consolas", 22, "bold"), text_color="green")
title_label.pack(pady=10)

# Entry with "Paste" button
entry_frame = ctk.CTkFrame(app, fg_color="transparent")
entry_frame.pack(pady=10)

url_entry = ctk.CTkEntry(entry_frame, width=420, placeholder_text="Enter URL here")
url_entry.pack(side="left", padx=(0, 5))

def paste_from_clipboard():
    url_entry.delete(0, 'end')
    url_entry.insert(0, app.clipboard_get())

paste_button = ctk.CTkButton(entry_frame, text="Paste", width=50, command=paste_from_clipboard,fg_color="green", hover_color="#006400")
paste_button.pack(side="left")

# Scan button
scan_button = ctk.CTkButton(app, text="Scan Website", command=start_scan, fg_color="green", hover_color="#006400")
scan_button.pack(pady=5)

# Progress bar
progress_bar = ctk.CTkProgressBar(app, width=460, height=8, corner_radius=8, progress_color="green")
progress_bar.pack(pady=5)
progress_bar.set(0)

# Result display
result_box = ctk.CTkLabel(app, text="", wraplength=500, justify="center")
result_box.pack(pady=20)

info_label = ctk.CTkLabel(app, text="Red = Malicious | Blue = Educational | Green = Safe | Orange = Suspicious", font=("Consolas", 12))
info_label.pack(side="bottom", pady=5)

# Theme toggle button (text only)
theme_button = ctk.CTkButton(app, text="Toggle Theme", command=toggle_theme, width=100, fg_color="#444", hover_color="#555", corner_radius=10)
theme_button.place(relx=0.96, rely=0.94, anchor="se")

app.mainloop()