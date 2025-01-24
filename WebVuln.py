import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import socket
import nmap

# Ensure the URL has a scheme (http or https)
def format_url(url):
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

# Extract hostname for Nmap
def get_hostname(url):
    return url.replace("http://", "").replace("https://", "").split('/')[0]

# Function to retrieve IP address
def get_ip_address(url):
    try:
        hostname = get_hostname(url)
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return f"Error resolving IP: {e}"

# Function to scan for open ports using Nmap
def scan_open_ports(ip_address):
    try:
        nm = nmap.PortScanner()
        results_text.insert(tk.END, "\nScanning for open ports...\n")
        nm.scan(hosts=ip_address, arguments='-p 1-1024')
        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                results_text.insert(tk.END, f"- Open {protocol} ports: {list(ports)}\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error during port scan: {e}\n")

# Function to check for security headers
def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        results_text.insert(tk.END, "\nChecking for Security Headers...\n")
        headers = {
            "Content-Security-Policy": "- Missing Content-Security-Policy header.\n",
            "X-Content-Type-Options": "- Missing X-Content-Type-Options header.\n",
            "Strict-Transport-Security": "- Missing Strict-Transport-Security header.\n",
            "X-Frame-Options": "- Missing X-Frame-Options header.\n",
            "Referrer-Policy": "- Missing Referrer-Policy header.\n"
        }
        for header, message in headers.items():
            if header not in response.headers:
                results_text.insert(tk.END, message)
    except Exception as e:
        results_text.insert(tk.END, f"Error checking Security Headers: {e}\n")

# Function to check XML-RPC vulnerability
def check_xmlrpc_vulnerability(url):
    try:
        xmlrpc_url = f"{url}/xmlrpc.php"
        response = requests.get(xmlrpc_url, timeout=10)
        if response.status_code == 200:
            if "XML-RPC server accepts POST requests only." in response.text:
                results_text.insert(tk.END, "- /xmlrpc.php is accessible. Potential vulnerability to brute force or DoS attacks.\n")
            else:
                results_text.insert(tk.END, "- /xmlrpc.php exists but is not fully accessible.\n")
        else:
            results_text.insert(tk.END, "- /xmlrpc.php is not accessible. Likely not vulnerable.\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error testing /xmlrpc.php: {e}\n")

# Function to test SQL Injection
def test_sql_injection(url):
    payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 'a'='a"]
    results_text.insert(tk.END, "\nTesting for SQL Injection vulnerabilities...\n")
    for payload in payloads:
        try:
            sql_url = f"{url}/{payload}"
            sql_response = requests.get(sql_url, timeout=10)
            if "error" in sql_response.text.lower() or "sql" in sql_response.text.lower():
                results_text.insert(tk.END, f"- SQL Injection vulnerability detected with payload: {payload}\n")
        except:
            results_text.insert(tk.END, f"Error testing SQL Injection with payload: {payload}\n")

# Function to test XSS
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    results_text.insert(tk.END, "\nTesting for XSS vulnerabilities...\n")
    try:
        xss_url = f"{url}?test={payload}"
        xss_response = requests.get(xss_url, timeout=10)
        if payload in xss_response.text:
            results_text.insert(tk.END, "- XSS vulnerability detected.\n")
    except:
        results_text.insert(tk.END, "Error testing XSS.\n")

# Function to perform vulnerability scanning
def scan_vulnerabilities():
    url = url_entry.get().strip()
    results_text.delete(1.0, tk.END)

    if not url:
        messagebox.showerror("Input Error", "Please enter a valid URL.")
        return

    # Format the URL and extract hostname
    formatted_url = format_url(url)
    hostname = get_hostname(formatted_url)

    try:
        # Get IP Address
        ip_address = get_ip_address(formatted_url)
        results_text.insert(tk.END, f"Website IP Address: {ip_address}\n")

        # Scan for open ports
        if "Error resolving IP" not in ip_address:
            scan_open_ports(ip_address)

        # Check Security Headers
        check_security_headers(formatted_url)

        # Test SQL Injection
        test_sql_injection(formatted_url)

        # Test XSS
        test_xss(formatted_url)

        # Check XML-RPC vulnerability
        results_text.insert(tk.END, "\nChecking for XML-RPC vulnerabilities...\n")
        check_xmlrpc_vulnerability(formatted_url)

        results_text.insert(tk.END, "\nScan completed.\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error during scan: {e}\n")

# GUI Setup
app = tk.Tk()
app.title("Advanced Vulnerability Scanner")

tk.Label(app, text="Enter Website URL:", font=("Arial", 12)).pack(pady=5)
url_entry = tk.Entry(app, width=50, font=("Arial", 12))
url_entry.pack(pady=5)

scan_button = tk.Button(app, text="Start Scan", command=scan_vulnerabilities, font=("Arial", 12), bg="green", fg="white")
scan_button.pack(pady=10)

results_text = scrolledtext.ScrolledText(app, width=80, height=20, font=("Courier", 10))
results_text.pack(pady=5)

tk.Label(app, text="Made By Feras Rabea : fr2sql@gmail.com", font=("Arial", 10), fg="gray").pack(pady=10)

app.mainloop()
