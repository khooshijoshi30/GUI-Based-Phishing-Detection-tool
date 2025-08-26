from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from tkinter import messagebox
from datetime import datetime
import customtkinter as ctk
from tkinter import filedialog
from PIL import Image, ImageDraw
import os
import threading
import nmap
import whois
from heuristics import calculate_phishing_score, fetch_openphish_feed
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import hashlib
import socket
import ssl
import requests
import ipaddress
import webbrowser
import json
import folium 
from heuristics import calculate_phishing_score, fetch_openphish_feed, get_server_info # you must install folium: pip install folium

last_scan_result_text = ""
verdict_counts = {"Phishing": 0, "Safe": 0}
last_whois_result = ""
last_nmap_result = ""

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

global_openphish_feed = fetch_openphish_feed()

app = ctk.CTk()
app.title("CID Cyber Cell - Phishing Detection Tool")
app.geometry("900x600")
app.minsize(800, 500)
app.resizable(True, True)

logo_path = r"C:\Users\ASUS\OneDrive\Desktop\gui\assets\cid_logo.jpg"
try:
    logo_image = ctk.CTkImage(dark_image=Image.open(logo_path), size=(80, 80))
except Exception:
    blank = Image.new("RGB", (80, 80), color="gray")
    draw = ImageDraw.Draw(blank)
    draw.text((10, 30), "No Logo", fill="white")
    logo_image = ctk.CTkImage(dark_image=blank, size=(80, 80))

main_frame = ctk.CTkFrame(app)
main_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Left Panel
left_panel = ctk.CTkFrame(main_frame, width=240, corner_radius=15)
left_panel.pack(side="left", fill="y", padx=(0, 10))

logo_label = ctk.CTkLabel(left_panel, image=logo_image, text="")
logo_label.pack(pady=(15, 5))

title_label = ctk.CTkLabel(left_panel, text="CID Phishing Tool", font=("Arial", 18, "bold"))
title_label.pack(pady=(5, 15))

url_entry = ctk.CTkEntry(left_panel, placeholder_text="Enter URL to Scan", width=200)
url_entry.pack(pady=10)

# Forward declarations for WHOIS/NMAP textboxes
whois_box = None
nmap_box = None

def reset_fields():
    url_entry.delete(0, "end")
    details_unsafe.configure(state="normal")
    details_unsafe.delete("1.0", "end")
    details_unsafe.configure(state="disabled")
    details_safe.configure(state="normal")
    details_safe.delete("1.0", "end")
    details_safe.configure(state="disabled")
    whois_box.configure(state="normal")
    whois_box.delete("1.0", "end")
    whois_box.insert("end", "Run a scan to view WHOIS info.")
    whois_box.configure(state="disabled")
    nmap_box.configure(state="normal")
    nmap_box.delete("1.0", "end")
    nmap_box.insert("end", "Run a scan to view Nmap results.")
    nmap_box.configure(state="disabled")

scan_button = ctk.CTkButton(left_panel, text="🔍 Scan URL", command=lambda: scan_url())
scan_button.pack(pady=5)

file_button = ctk.CTkButton(left_panel, text="📂 Scan .txt File", command=lambda: scan_file())
file_button.pack(pady=5)

reset_button = ctk.CTkButton(left_panel, text="🔄 Reset", command=lambda: reset_fields(),
                             fg_color="#888", hover_color="#444")
reset_button.pack(pady=10)

def show_verdict_chart():
    labels = ['Phishing', 'Safe']
    sizes = [verdict_counts["Phishing"], verdict_counts["Safe"]]
    colors = ['red', 'green']
    plt.clf()
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct='%1.0f%%', startangle=90, counterclock=False)
    ax.axis('equal')
    ax.set_title("Verdict Distribution (Safe vs Phishing)")

    chart_window = ctk.CTkToplevel(app)
    chart_window.title("Verdict Distribution")
    chart_window.geometry("400x400")

    canvas_chart = FigureCanvasTkAgg(fig, master=chart_window)
    canvas_chart.draw()
    canvas_chart.get_tk_widget().pack(fill="both", expand=True)

chart_button = ctk.CTkButton(left_panel, text="📊 Show Verdict Chart", command=show_verdict_chart)
chart_button.pack(pady=10)

ctk.CTkLabel(left_panel, text="Theme", font=("Arial", 14, "bold")).pack(pady=(20, 5))
theme_switch_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
theme_switch_frame.pack(pady=(0, 10))

ctk.CTkButton(theme_switch_frame, text="🌙 Dark", width=100,
              command=lambda: ctk.set_appearance_mode("Dark")).pack(side="left", padx=2)
ctk.CTkButton(theme_switch_frame, text="☀️ Light", width=100,
              command=lambda: ctk.set_appearance_mode("Light")).pack(side="left", padx=2)

# Right Panel
right_panel = ctk.CTkFrame(main_frame, corner_radius=15)
right_panel.pack(side="left", fill="both", expand=True)

ctk.CTkLabel(right_panel, text="🔴 Unsafe Links", font=("Arial", 16, "bold"),
             text_color="white", bg_color="red").pack(fill="x", pady=(10, 0), padx=10)
details_unsafe = ctk.CTkTextbox(right_panel, height=150, wrap="word")
details_unsafe.pack(fill="both", expand=True, padx=10, pady=(0, 10))
details_unsafe.insert("end", "")
details_unsafe.configure(state="disabled")

ctk.CTkLabel(right_panel, text="🟢 Safe Links", font=("Arial", 16, "bold"),
             text_color="white", bg_color="green").pack(fill="x", pady=(10, 0), padx=10)
details_safe = ctk.CTkTextbox(right_panel, height=150, wrap="word")
details_safe.pack(fill="both", expand=True, padx=10, pady=(0, 10))
details_safe.insert("end", "")
details_safe.configure(state="disabled")

# WHOIS and Nmap Sections
whois_label = ctk.CTkLabel(right_panel, text="🔎 WHOIS Domain Information", font=("Arial", 16, "bold"))
whois_label.pack(fill="x", pady=(10, 0), padx=10)
whois_box = ctk.CTkTextbox(right_panel, height=120, wrap="word")
whois_box.pack(fill="both", expand=False, padx=10, pady=(0, 10))
whois_box.insert("end", "Run a scan to view WHOIS info.")
whois_box.configure(state="disabled")

nmap_label = ctk.CTkLabel(right_panel, text="🛡️ Nmap Scan Results", font=("Arial", 16, "bold"))
nmap_label.pack(fill="x", pady=(10, 0), padx=10)
nmap_box = ctk.CTkTextbox(right_panel, height=120, wrap="word")
nmap_box.pack(fill="both", expand=False, padx=10, pady=(0, 10))
nmap_box.insert("end", "Run a scan to view Nmap results.")
nmap_box.configure(state="disabled")

# --- SSL Info ---
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                issued_on = cert.get('notBefore')
                expires_on = cert.get('notAfter')
                return (
                    f"--- SSL Certificate ---\n"
                    f"Issuer: {issuer.get('organizationName', str(issuer))}\n"
                    f"Subject: {subject.get('commonName', str(subject))}\n"
                    f"Issued On: {issued_on}\n"
                    f"Expires On: {expires_on}\n"
                )
    except Exception as e:
        return f"--- SSL Certificate ---\nSSL info could not be retrieved: {e}\n"

# --- Geolocation Info (IP-API, no API key needed) ---
def get_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        if data['status'] != 'success':
            return f"--- Geolocation ---\nGeolocation not available.\n"
        return (
            f"--- Geolocation ---\n"
            f"Country: {data.get('country', 'N/A')}\n"
            f"Region: {data.get('regionName', 'N/A')}\n"
            f"City: {data.get('city', 'N/A')}\n"
            f"ISP: {data.get('isp', 'N/A')}\n"
            f"Latitude: {data.get('lat', 'N/A')}\n"
            f"Longitude: {data.get('lon', 'N/A')}\n"
        )
    except Exception as e:
        return f"--- Geolocation ---\nGeolocation info could not be retrieved: {e}\n"

def reverse_dns(ip):
    try:
        return f"--- Reverse DNS ---\nPTR Record: {socket.gethostbyaddr(ip)[0]}\n"
    except Exception:
        return "--- Reverse DNS ---\nPTR Record: Not found\n"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        exp = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(exp, list): exp = exp[0]
        now = datetime.utcnow()
        domain_age = (now - creation).days if creation else "N/A"
        info = (
            f"WHOIS Domain Information:\n"
            f"-----------------------------\n"
            f"Domain: {w.domain_name}\n"
            f"Registrar: {w.registrar}\n"
            f"Creation Date: {creation}\n"
            f"Expiry Date: {exp}\n"
            f"Domain Age: {domain_age} days\n"
            f"Registrant Country: {w.country}\n"
            f"WHOIS Status: Retrieved\n"
        )
        return info
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# ---- Nmap function supporting IPv4 and IPv6 ----
def get_nmap_info(target):
    try:
        nm = nmap.PortScanner()
        arguments = '-F'
        # Detect if target is IPv6
        try:
            ip = ipaddress.ip_address(target)
            if ip.version == 6:
                arguments = '-6 ' + arguments
        except ValueError:
            if ':' in target and not target.replace(':', '').replace('.', '').isdigit():
                arguments = '-6 ' + arguments
        nm.scan(target, arguments=arguments)
        output = f"Nmap Scan Results:\n------------------\nTarget: {target}\n"
        for host in nm.all_hosts():
            output += f"IP Address: {host}\n"
            if 'tcp' in nm[host]:
                output += "Open Ports:\n"
                for port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    name = nm[host]['tcp'][port]['name']
                    output += f"- {port}/tcp ({name}) [{state}]\n"
        if len(nm.all_hosts()) == 0:
            output += "No open ports discovered or host unreachable.\n"
        return output
    except Exception as e:
        return f"Nmap scan failed: {e}"

def get_hashes(text):
    md5 = hashlib.md5(text.encode('utf-8')).hexdigest()
    sha1 = hashlib.sha1(text.encode('utf-8')).hexdigest()
    sha256 = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return md5, sha1, sha256

def fetch_redirect_chain(domain):
    try:
        resp = requests.get(f"https://web-check-latest.onrender.com/api/redirects?url={domain}", timeout=7)
        resp.raise_for_status()
        data = resp.json()
        return data.get("redirects", ["No redirects found"])
    except Exception as e:
        return [f"Error fetching redirect chain: {e}"]

def fetch_linked_pages(domain):
    try:
        resp = requests.get(f"https://web-check-latest.onrender.com/api/linked-pages?url={domain}", timeout=7)
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(data, indent=2)
    except Exception as e:
        return f"Error fetching linked pages: {e}"

def fetch_ip_from_domain(domain):
    try:
        resp = requests.get(f"http://web-check-latest.onrender.com/api/get-ip?url={domain}", timeout=7)
        resp.raise_for_status()
        data = resp.json()
        ip = data.get("A", {}).get("address") or data.get("ip")
        return json.dumps(data, indent=2), ip
    except Exception as e:
        return f"Error retrieving IP: {e}", None

def fetch_geo_from_ip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=7)
        resp.raise_for_status()
        data = resp.json()
        return json.dumps(data, indent=2), data
    except Exception as e:
        return f"Error retrieving geolocation: {e}", None

def create_geo_map(lat, lon, domain):
    try:
        map_obj = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], popup=domain).add_to(map_obj)
        map_file = f"{domain}_location_map.html"
        map_obj.save(map_file)
        return map_file
    except Exception as e:
        return None

def open_map(map_file):
    if map_file and os.path.exists(map_file):
        webbrowser.open(f"file://{os.path.abspath(map_file)}")
    else:
        messagebox.showwarning("Map not available", "Map file not found or not generated yet.")

last_map_file = None  # Add this at module level (global)

def scan_url():
    url = url_entry.get().strip()
    if not url:
        return

    def process():
        global last_scan_result_text, verdict_counts, last_whois_result, last_nmap_result, last_map_file
        try:
            md5, sha1, sha256 = get_hashes(url)
            hash_lines = (
                f"--- Hash Values ---\n"
                f"MD5:    {md5}\n"
                f"SHA1:   {sha1}\n"
                f"SHA256: {sha256}\n"
            )
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = calculate_phishing_score(url, openphish_feed=global_openphish_feed)
            score = result['score']
            is_phishing = result['is_phishing']
            details = result['details']
            server_info = get_server_info(url)
            reason = details.get('phishing_reason', '')
            domain = url.replace("http://", "").replace("https://", "").split('/')[0]

            ip_addresses = details.get('ip_addresses', [])
            ip_lines = "\n".join(ip_addresses) if ip_addresses else "No IP address found"
            ip_for_extras = ip_addresses[0] if ip_addresses else None
            nmap_target = ip_for_extras if ip_for_extras else domain

            heuristics = details['heuristics']
            heuristics_lines = "\n".join(
                [f"- {k.replace('_', ' ').capitalize()}: {'Yes' if v else 'No'}" for k, v in heuristics.items()]
            )

            vt = details.get('virustotal')
            vt_line = f"VirusTotal: {vt}" if vt else "VirusTotal: Not checked"
            gs = f"Google Safe Browsing: {'Flagged' if details.get('google_safe_browsing') else 'Not flagged'}"
            op = f"OpenPhish: {'Listed' if details.get('openphish') else 'Not listed'}"
            abuse_score = details.get('abuseipdb_score')
            abuse = f"AbuseIPDB Score: {abuse_score if abuse_score is not None else 'N/A'}"

            whois_info = get_whois_info(domain)
            nmap_info = get_nmap_info(nmap_target)
            ssl_info = get_ssl_info(domain)
            geolocation_info = get_geolocation(ip_for_extras) if ip_for_extras else "--- Geolocation ---\nNot available\n"
            reverse_dns_info = reverse_dns(ip_for_extras) if ip_for_extras else "--- Reverse DNS ---\nNot available\n"

            subdomains_text = "\n".join(details.get('subdomains', [])) if isinstance(details.get('subdomains'), list) else details.get('subdomains', "")
            ip_history_text = details.get("ip_history", "")
            dns_report_text = details.get("dns_report", "")
            redirect_chain = details.get('redirect_domains', [])
            linked_pages_json = details.get('linked_pages_json', 'No data')
            ip_json = details.get('ip_json', 'No data')
            geo_json = details.get('geo_json', 'No data')
            reverse_whois_domains = details.get('reverse_whois_domains', ["No data"])
            map_file = details.get('map_file', None)

            output = (
                f"Scan Time: {scan_time}\n"
                f"{'Reason: ' + reason + '\n' if reason else ''}"
                f"Score: {score}\n\n"
                f"{hash_lines}\n"
                f"--- Domain IP Addresses ---\n{ip_lines}\n\n"
                f"--- Heuristics ---\n{heuristics_lines}\n\n"
                f"--- External Checks ---\n{vt_line}\n{gs}\n{op}\n{abuse}\n\n"
                f"{whois_info}\n\n"
                f"{nmap_info}\n\n"
                f"{ssl_info}\n\n"
                f"{geolocation_info}\n"
                f"{reverse_dns_info}\n"
                f"--- Subdomains (crt.sh) ---\n{subdomains_text}\n\n"
                f"--- IP History ---\n{ip_history_text}\n\n"
                f"--- DNS Report ---\n{dns_report_text}\n\n"
                f"--- Redirect Chain ---\n"
                f"{chr(10).join(redirect_chain) if isinstance(redirect_chain, list) else str(redirect_chain)}\n\n"
                f"--- Linked Pages ---\n{linked_pages_json}\n\n"
                f"--- Domain to IP ---\n{ip_json}\n\n"
                f"--- IP Geolocation ---\n{geo_json}\n\n"
                f"--- Server Info ---\n{server_info}\n\n"
            )

            last_scan_result_text = output
            last_whois_result = whois_info
            last_nmap_result = nmap_info

            details_unsafe.configure(state="normal")
            details_safe.configure(state="normal")
            details_unsafe.delete("1.0", "end")
            details_safe.delete("1.0", "end")
            whois_box.configure(state="normal")
            whois_box.delete("1.0", "end")
            whois_box.insert("end", whois_info)
            whois_box.configure(state="disabled")
            nmap_box.configure(state="normal")
            nmap_box.delete("1.0", "end")
            nmap_box.insert("end", nmap_info)
            nmap_box.configure(state="disabled")

            if is_phishing:
                details_unsafe.insert("end", output)
                verdict_counts["Phishing"] += 1
            else:
                details_safe.insert("end", output)
                verdict_counts["Safe"] += 1

            details_unsafe.configure(state="disabled")
            details_safe.configure(state="disabled")

            # Map button logic (optional)
            def on_show_map():
                if map_file and os.path.exists(map_file):
                    webbrowser.open(f"file://{os.path.abspath(map_file)}")
                else:
                    messagebox.showwarning("Map Not Available", "No map file was generated for this scan.")

            if not hasattr(left_panel, "map_button"):
                left_panel.map_button = ctk.CTkButton(left_panel, text="🗺 Show Geo Map", command=on_show_map)
                left_panel.map_button.pack(pady=(10, 0), padx=10)
            else:
                left_panel.map_button.configure(command=on_show_map)

        except Exception as e:
            logger.warning(f"Exception during scan processing: {e}")
            details_unsafe.configure(state="normal")
            details_unsafe.delete("1.0", "end")
            details_unsafe.insert("end", str(e))
            details_unsafe.configure(state="disabled")

    threading.Thread(target=process, daemon=True).start()
        

def scan_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return

    def process():
        global last_scan_result_text, verdict_counts, last_whois_result, last_nmap_result
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file if line.strip()]

        details_unsafe.configure(state="normal")
        details_safe.configure(state="normal")
        details_unsafe.delete("1.0", "end")
        details_safe.delete("1.0", "end")

        combined_output = []

        for i, url in enumerate(lines, 1):
            try:
                result = calculate_phishing_score(url, openphish_feed=global_openphish_feed)
                score = result['score']
                is_phishing = result['is_phishing']
                details = result['details']
                reason = details.get('phishing_reason', '')

                verdict = "Phishing" if is_phishing else "Safe"
                summary = f"{i}. {url} -> {verdict} (Score: {score})\n"
                if reason:
                    summary += f"   Reason: {reason}\n"

                # Existing fields
                redirect_domains = details.get("redirect_domains", [])
                redirects_text = "\n".join(redirect_domains) if isinstance(redirect_domains, list) else str(redirect_domains)

                linked_pages_json = details.get("linked_pages_json", "No data")
                ip_json = details.get("ip_json", "No data")
                geo_json = details.get("geo_json", "No data")
                reverse_whois_domains = details.get("reverse_whois_domains", ["No data"])
                map_file = details.get("map_file", None)
                server_info = get_server_info(url)
                details['server_info'] = server_info



                # Append all new API info into summary
                summary += f"--- Redirecting Domains (URLScan.io) ---\n{redirects_text}\n\n"
                summary += f"--- Linked Pages ---\n{linked_pages_json}\n\n"
                summary += f"--- Domain to IP ---\n{ip_json}\n\n"
                summary += f"--- IP Geolocation ---\n{geo_json}\n\n"
                summary += f"--- Server Info ---\n{server_info}\n\n"

                if is_phishing:
                    details_unsafe.insert("end", summary + "\n")
                    verdict_counts["Phishing"] += 1
                else:
                    details_safe.insert("end", summary + "\n")
                    verdict_counts["Safe"] += 1

                combined_output.append(summary)

            except Exception as e:
                error_msg = f"{i}. {url} -> Error: {e}\n"
                details_unsafe.insert("end", error_msg)
                combined_output.append(error_msg)

        details_unsafe.configure(state="disabled")
        details_safe.configure(state="disabled")

        last_scan_result_text = "\n".join(combined_output)

    threading.Thread(target=process, daemon=True).start()

def save_report_to_pdf(content, filename="phishing_report.pdf"):
    try:
        width, height = letter
        logo_width = 80
        logo_height = 80
        x_pos = (width - logo_width) / 2
        y_pos = height - 100
        c = canvas.Canvas(filename, pagesize=letter)
        y_position = y_pos - 20  # Start text below the logo

        lines = content.strip().split('\n')
        try:
            c.drawImage(logo_path, x_pos, y_pos, width=logo_width, height=logo_height, mask='auto')
        except Exception:
            y_position = height - 40

        for line in lines:
            if y_position < 40:
                c.showPage()
                try:
                    c.drawImage(logo_path, x_pos, y_pos, width=logo_width, height=logo_height, mask='auto')
                    y_position = y_pos - 20
                except Exception:
                    y_position = height - 40
            c.drawString(40, y_position, line)
            y_position -= 15

        c.save()
        messagebox.showinfo("Success", f"PDF saved as {filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save PDF: {e}")

def download_pdf():
    global last_scan_result_text
    if not last_scan_result_text.strip():
        messagebox.showwarning("No Data", "No scan data available to export.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"phishing_report_{timestamp}.pdf"
    file_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        initialfile=default_name,
        title="Save Report As"
    )
    if file_path:
        save_report_to_pdf(last_scan_result_text, filename=file_path)

pdf_button = ctk.CTkButton(left_panel, text="📄 Download as PDF", command=download_pdf)
pdf_button.pack(pady=10)

app.mainloop()
