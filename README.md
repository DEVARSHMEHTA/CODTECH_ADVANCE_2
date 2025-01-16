# CODTECH_ADVANCE_2
# WEB APPLICATION VULNERABILITY SCANNER
## Details
- Name    : Devarsh Mehta
- Company : CODTECH IT SOLUTIONS PVT.LTD
- ID      : CT08DAL
- Domain  : Cyber Security & Ethical Hacking
- Duration: 20th Dec 2024 To 20th Jan 2025
- Mentor  : Neela Santhosh Kumar

## Overview
A Python-based web vulnerability scanner that identifies common security flaws in web applications. It supports detecting **XSS (Cross-Site Scripting)** and **SQL Injection** vulnerabilities. The tool is designed for ethical hacking and penetration testing purposes, ensuring a secure web environment.

## Features
- **XSS Vulnerabilities**
  - Reflected XSS
  - DOM-based XSS
  - Stored XSS
- **SQL Injection Vulnerabilities**
  - Standard SQL Injection
  - Blind SQL Injection
- **Web Crawler**
  - Automatically crawls the website to discover pages and forms for scanning.
- **Custom Payload Support**
  - Accepts custom payload files for both XSS and SQL Injection testing.
- **User-Agent Spoofing**
  - Mimics a real browser to avoid detection by basic firewalls.
## Requirements
- Python 3.6+
- Required libraries:
  - `requests`
  - `beautifulsoup4`
  - `colorama`
  - `pyfiglet`

You can install the required packages using pip:

```bash
pip install requests beautifulsoup4 colorama pyfiglet
```
## Usage
1. Clone or download the repository.

2. Open a terminal and navigate to the project directory.

3. Provide Executable Permission.  

4. Run the web-scanner.py script:

## Commands Paste It on terminal

```sh
git clone https://github.com/DEVARSHMEHTA/CODTECH_ADVANCE_2.git
```

```sh
cd CODTECH_ADVANCE_2
```

```sh
pip install -r requirements.txt
```

```sh
chmod +x web-scanner.py
```

```sh
python3 web-scanner.py
```
## Example Output
![image](https://github.com/user-attachments/assets/dad5d07f-2db5-49fd-a255-6902354d1f0a)

![image](https://github.com/user-attachments/assets/e3974190-4a62-4368-9581-a48dfe0b952e)


## Author
- Devarsh Mehta
- [GitHub Profile](https://github.com/DEVARSHMEHTA)

## Acknowledgments

- [pyfiglet](https://github.com/pwaller/pyfiglet): ASCII art generation
- [termcolor](https://pypi.org/project/termcolor/): Colored terminal text
