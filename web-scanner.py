import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import init, Fore
import pyfiglet
import os

# Initialize colorama
init(autoreset=True)

# Display banner and creator information
figlet_banner = pyfiglet.figlet_format("WEB-SCANNER")
creator_info = "[i] -- Developed by Devarsh Mehta--"

print(Fore.CYAN + figlet_banner)
print(Fore.CYAN + creator_info)

# Set to keep track of visited URLs to avoid repetition
visited_urls = set()

# Custom headers to mimic a web browser request
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Function to fetch payloads from a specified file
def read_payloads_from_file(filepath):
    with open(filepath, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Function to select payloads based on user choice
def select_payloads(option):
    if option == '1':
        xss_payload_path = input(Fore.BLUE + "[*] Enter the path to the XSS payload file: ")
        xss_payloads = read_payloads_from_file(xss_payload_path)
        return None, xss_payloads
    elif option == '2':
        sql_injection_payload_path = input(Fore.BLUE + "[*] Enter the path to the SQL Injection payload file: ")
        sql_injection_payloads = read_payloads_from_file(sql_injection_payload_path)
        return sql_injection_payloads, None
    return [], []

# Recursive function to crawl the website
def web_crawler(url, base_url, depth=0, max_depth=2):
    if depth > max_depth:
        return []
    
    urls_to_scan = []
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(base_url, link['href'])
            if base_url in absolute_url and absolute_url not in visited_urls:
                visited_urls.add(absolute_url)
                urls_to_scan.append(absolute_url)
                urls_to_scan.extend(web_crawler(absolute_url, base_url, depth + 1, max_depth))
    except requests.RequestException as e:
        print(Fore.RED + f"Error crawling {url}: {e}")
    return urls_to_scan

# Function to test for standard SQL Injection vulnerabilities
def test_sql_injection(url, params, sql_injection_payloads):
    if not sql_injection_payloads:
        return
    
    for payload in sql_injection_payloads:
        for param in params:
            full_url = f"{url}?{param}={payload.strip()}"
            try:
                response = requests.get(full_url, headers=headers)
                response.raise_for_status()
                error_indicators = ["syntax error", "sql error", "database error", "query failed", "warning: mysql", "invalid query", "unclosed quotation mark", "you have an error in your sql syntax"]
                if any(keyword in response.text.lower() for keyword in error_indicators):
                    print(f"{Fore.BLUE}[+] Detected standard SQL Injection vulnerability at {url}{Fore.RESET}")
                    print(Fore.YELLOW + f"Payload: {payload} for Parameter: {param}")
            except requests.RequestException:
                pass

# Function to test for Blind SQL Injection vulnerabilities
def test_blind_sql_injection(url, params, sql_injection_payloads):
    if not sql_injection_payloads:
        return

    for payload in sql_injection_payloads:
        for param in params:
            full_url = f"{url}?{param}={payload.strip()}"
            try:
                response = requests.get(full_url, headers=headers, timeout=10)
                response.raise_for_status()
                if response.elapsed.total_seconds() > 5:  # Check for time delay
                    print(f"{Fore.BLUE}[+] Detected blind SQL Injection vulnerability at {url}{Fore.RESET}")
                    print(Fore.YELLOW + f"Payload: {payload} for Parameter: {param}")
            except requests.RequestException:
                pass

# Function to test for Reflected XSS vulnerabilities
def test_reflected_xss(url, params, xss_payloads):
    if not xss_payloads:
        return
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return
        
        for form in forms:
            action = form.get('action')
            if action:
                absolute_url = urljoin(url, action)
                for payload in xss_payloads:
                    data = {input_tag.get('name'): payload.strip() for input_tag in form.find_all(['input', 'textarea']) if input_tag.get('name')}
                    for param, value in data.items():
                        try:
                            form_response = requests.post(absolute_url, data={param: value}, headers=headers)
                            form_response.raise_for_status()
                            if payload in form_response.text:
                                print(f"{Fore.BLUE}[+] Detected reflected XSS vulnerability at {url}{Fore.RESET}")
                                print(Fore.YELLOW + f"Payload: {payload} for Parameter: {param}")
                        except requests.RequestException:
                            pass
    except requests.RequestException:
        pass

# Function to test for DOM-based XSS vulnerabilities
def test_dom_based_xss(url, xss_payloads):
    if not xss_payloads:
        return

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        for payload in xss_payloads:
            if payload in response.text:
                print(f"{Fore.BLUE}[+] Detected DOM-based XSS vulnerability at {url}{Fore.RESET}")
                print(Fore.YELLOW + f"Payload: {payload}")
    except requests.RequestException:
        pass

# Function to test for Stored XSS vulnerabilities
def test_stored_xss(url, xss_payloads):
    if not xss_payloads:
        return

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return

        for form in forms:
            action = form.get('action')
            if action:
                absolute_url = urljoin(url, action)
                for payload in xss_payloads:
                    data = {input_tag.get('name'): payload.strip() for input_tag in form.find_all(['input', 'textarea']) if input_tag.get('name')}
                    try:
                        form_response = requests.post(absolute_url, data=data, headers=headers)
                        form_response.raise_for_status()
                        if payload in form_response.text:
                            print(f"{Fore.BLUE}[+] Detected stored XSS vulnerability at {url}{Fore.RESET}")
                            print(Fore.YELLOW + f"Payload: {payload}")
                    except requests.RequestException:
                        pass
    except requests.RequestException:
        pass

# Function to extract form input parameters from the webpage
def extract_input_parameters(url):
    params = []
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            for input_tag in form.find_all(['input', 'textarea']):
                name = input_tag.get('name')
                if name and name not in params:
                    params.append(name)
    except requests.RequestException:
        pass
    return params

# Main function to execute the vulnerability scan
def execute_vulnerability_scan():
    url = input(Fore.BLUE + "[*] Enter the URL of the web application to scan: ")
    print(Fore.BLUE + "[*] Select the type of scan:")
    print(Fore.YELLOW + "[1] XSS Scan (Reflected, DOM-based, Stored)")
    print(Fore.YELLOW + "[2] SQL Injection Scan (Standard, Blind)")
    choice = input(Fore.BLUE + "[?] Enter your choice (1/2): ")
    
    if choice not in ['1', '2']:
        print(Fore.RED + "[-] Invalid choice. Exiting...")
        return

    print(Fore.BLUE + "[*] Starting the vulnerability scan...")
    base_url = '{uri.scheme}://{uri.netloc}'.format(uri=urlparse(url))
    sql_injection_payloads, xss_payloads = select_payloads(choice)
    urls_to_scan = web_crawler(url, base_url)
    
    for scan_url in urls_to_scan:
        params = extract_input_parameters(scan_url)
        if choice == '1':
            test_reflected_xss(scan_url, params, xss_payloads)
            test_dom_based_xss(scan_url, xss_payloads)
            test_stored_xss(scan_url, xss_payloads)
        elif choice == '2':
            test_sql_injection(scan_url, params, sql_injection_payloads)
            test_blind_sql_injection(scan_url, params, sql_injection_payloads)
    
    print(Fore.BLUE + "[*] Vulnerability scan completed.")

if __name__ == "__main__":
    execute_vulnerability_scan()
