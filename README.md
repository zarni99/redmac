# RedMac

**RedMac** is a comprehensive, automated Bash script designed to set up a robust penetration testing and security research environment on macOS. It streamlines the installation of essential CLI tools, GUI applications, Python packages, and specialized payloads, ensuring you have a ready-to-use toolkit in minutes.

## Features
- Installs Homebrew if needed and sets up a macOS security toolkit
- Uses a dedicated Python venv and links tool binaries into your PATH
- Installs common CLI tools, GUI apps, Python packages, and payloads in one run

## Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/zarni99/redmac.git
    cd redmac
    ```

2.  **Make the script executable**:
    ```bash
    chmod +x redmac.sh
    ```

3.  **Run the script**:
    ```bash
    ./redmac.sh
    ```

## Included Tools

### Brew Formulae (CLI)
nmap, masscan, hydra, hashcat, john, aircrack-ng, gobuster, sqlmap, nikto, theharvester, amass, ffuf, rustscan, proxychains-ng, tor, nuclei, subfinder, httpx, naabu, exploitdb, feroxbuster, binwalk, socat, sslscan, wget, cmake, openssl@3, tmux, jq, radare2, apktool.

### Brew Casks (GUI)
Wireshark, Metasploit, Mitmproxy, OWASP ZAP, Postman

### Python Packages
impacket, dirsearch, wafw00f, arjun, frida-tools, objection, hashid

### Standalone Payloads & Scripts
Chisel, LinPEAS/WinPEAS, LinEnum, Linux Exploit Suggester, LSE, pspy, PowerUp, Nishang reverse shell, PHP reverse shell, PrintSpoofer, TokenBreaker, JWT cracker, Hash Identifier, LinkFinder, plus small helper scripts.

## Logging

The installation process logs all activities to:
```bash
~/.redmac-install.log
```
Check this file if any installation steps fail.

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**. Using these tools to attack targets without prior mutual consent is illegal. The authors assume no liability for any misuse or damage caused by this program.
