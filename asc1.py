import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import requests
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 8080: "HTTP-ALT"
}

def get_prefixes(asn):
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        res = requests.get(url)
        data = res.json()
        prefixes = []
        if "ipv4_prefixes" in data.get("data", {}):
            prefixes = [p["prefix"] for p in data["data"]["ipv4_prefixes"]]
        return prefixes
    except Exception as e:
        return []

def get_ip_list_from_cidr(cidr, limit=50):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in net.hosts()][:limit]
    except:
        return []

def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in [80, 8080, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = b""
            while True:
                part = s.recv(4096)
                if not part:
                    break
                banner += part
                if len(banner) > 4096:
                    break
            return banner.decode(errors="ignore").strip()
    except:
        return ""

def scan_host(ip, full_scan=False):
    open_ports = []
    ports_to_scan = range(0, 65536) if full_scan else COMMON_PORTS.keys()
    for port in ports_to_scan:
        try:
            with socket.create_connection((ip, port), timeout=1):
                banner = grab_banner(ip, port)
                service_name = COMMON_PORTS.get(port, "Unknown")
                open_ports.append((port, service_name, banner))
        except:
            pass
    return ip, open_ports

def scan_asn(asn, limit, threads, full_scan, output_widget, btn_start):
    btn_start.config(state=tk.DISABLED)
    output_widget.delete(1.0, tk.END)
    output_widget.insert(tk.END, f"[+] Getting prefixes for {asn}...\n")
    prefixes = get_prefixes(asn)
    if not prefixes:
        output_widget.insert(tk.END, "[-] Failed to get prefixes or ASN invalid.\n")
        btn_start.config(state=tk.NORMAL)
        return
    all_ips = []
    for p in prefixes:
        ips = get_ip_list_from_cidr(p, limit)
        all_ips.extend(ips)
    output_widget.insert(tk.END, f"[+] Found {len(prefixes)} prefixes, scanning {len(all_ips)} IPs...\n")

    def update_output(text):
        output_widget.insert(tk.END, text)
        output_widget.see(tk.END)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = executor.map(lambda ip: scan_host(ip, full_scan), all_ips)
        for ip, ports in futures:
            if ports:
                update_output(f"{ip}:\n")
                for p, s, b in ports:
                    update_output(f"  Port {p} ({s}):\n{b}\n{'-'*30}\n")
    update_output("[+] Scan complete.\n")
    btn_start.config(state=tk.NORMAL)

def start_scan_thread(asn_entry, limit_entry, threads_entry, fullscan_var, output_widget, btn_start):
    asn = asn_entry.get().strip()
    if not asn.startswith("AS") or not asn[2:].isdigit():
        messagebox.showerror("Input Error", "ASN harus diawali 'AS' diikuti angka, misal AS13335")
        return
    try:
        limit = int(limit_entry.get())
        threads = int(threads_entry.get())
    except:
        messagebox.showerror("Input Error", "Limit dan Threads harus angka valid")
        return
    full_scan = fullscan_var.get()
    threading.Thread(target=scan_asn, args=(asn, limit, threads, full_scan, output_widget, btn_start), daemon=True).start()

def save_output(output_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(output_widget.get(1.0, tk.END))
        messagebox.showinfo("Save File", f"File berhasil disimpan: {file_path}")

# GUI setup
root = tk.Tk()
root.title("ASN Scanner GUI")

tk.Label(root, text="ASN (misal AS13335):").grid(row=0, column=0, sticky="w")
asn_entry = tk.Entry(root, width=20)
asn_entry.grid(row=0, column=1, pady=5)

tk.Label(root, text="Limit IP per prefix:").grid(row=1, column=0, sticky="w")
limit_entry = tk.Entry(root, width=20)
limit_entry.insert(0, "10")
limit_entry.grid(row=1, column=1, pady=5)

tk.Label(root, text="Threads:").grid(row=2, column=0, sticky="w")
threads_entry = tk.Entry(root, width=20)
threads_entry.insert(0, "10")
threads_entry.grid(row=2, column=1, pady=5)

fullscan_var = tk.BooleanVar()
fullscan_check = tk.Checkbutton(root, text="Full Port Scan (0-65535)", variable=fullscan_var)
fullscan_check.grid(row=3, column=0, columnspan=2, sticky="w")

btn_start = tk.Button(root, text="Start Scan", command=lambda: start_scan_thread(asn_entry, limit_entry, threads_entry, fullscan_var, output_text, btn_start))
btn_start.grid(row=4, column=0, columnspan=2, pady=10)

output_text = scrolledtext.ScrolledText(root, width=80, height=30)
output_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

btn_save = tk.Button(root, text="Save Output", command=lambda: save_output(output_text))
btn_save.grid(row=6, column=0, columnspan=2, pady=5)

root.mainloop()
