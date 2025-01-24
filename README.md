# WebVuln
Web Vulnerability Scanner: A Python tool with a GUI to test websites for SQL Injection, XSS, Directory Traversal, Open Redirects, WordPress vulnerabilities, and missing security headers. Integrates Nmap for open port scanning. Easy-to-use and great for web security testing!
Before running the script, ensure the following dependencies are installed on your system:

python3 --version

Install Required Libraries
Run the following command to install all necessary Python packages:

pip install requests python-nmap

Install Nmap (for Port Scanning)
Nmap must be installed separately on your system:

    Linux:

sudo apt install nmap

Windows: Download Nmap
MacOS:

        brew install nmap

Usage

    Clone this repository:

git clone https://github.com/ferasarabea/webvuln.git
cd webvuln

Run the script:

python3 webvuln.py

Input a URL (e.g., https://example.com) into the provided field and click Start Scan.

View the results in the output window.
