import socket
import threading
import requests
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from tqdm import tqdm

# إعداد تسجيل الأخطاء
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Text colors
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"
BOLD = "\033[1m"

class QWepScan:
    def __init__(self, target):
        """
        الدالة البنائية: تقوم بتهيئة الكائن وتحديد الهدف
        :param target: عنوان الهدف (IP أو URL)
        """
        self.target = target
        self.ip = None
        self.open_ports = []  # قائمة لتخزين المنافذ المفتوحة
        self.report = ""  # تقرير الفحص
        try:
            self.ip = socket.gethostbyname(target)  # تحويل الاسم إلى عنوان IP
        except socket.gaierror as e:
            logging.error(f"Error resolving target '{target}': {e}")
            print(f"{RED}[!] Error resolving target. Please check the URL or IP.{RESET}")
            sys.exit(1)

    def scan_port(self, port):
        """
        دالة لفحص المنفذ المحدد
        :param port: المنفذ الذي سيتم فحصه
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.ip, port))  # محاولة الاتصال بالمنفذ
            if result == 0:  # إذا تم الاتصال بنجاح
                print(f"{GREEN}[+] Port {port} is open{RESET}")
                self.open_ports.append(port)
                self.report += f"Port {port} is open\n"
            sock.close()
        except socket.error as e:
            logging.error(f"Error scanning port {port}: {e}")
            print(f"{RED}[!] Error scanning port {port}: {e}{RESET}")
        except Exception as e:
            logging.error(f"Unexpected error scanning port {port}: {e}")
            print(f"{RED}[!] Unexpected error scanning port {port}: {e}{RESET}")

    def port_scanner(self, ports):
        """
        دالة لفحص مجموعة من المنافذ باستخدام ThreadPoolExecutor
        :param ports: قائمة المنافذ التي سيتم فحصها
        """
        if not ports:
            logging.warning("Port list is empty. No ports to scan.")
            print(f"{YELLOW}[!] No ports to scan.{RESET}")
            return
        
        print("[+] Scanning ports...")
        try:
            # استخدام ThreadPoolExecutor مع as_completed لتقليل التأخير
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                for future in tqdm(as_completed(futures), total=len(ports), desc="Scanning Progress"):
                    future.result()  # ننتظر إتمام المهمة
        except Exception as e:
            logging.error(f"Error during port scanning: {e}")
            print(f"{RED}[!] Error during port scanning: {e}{RESET}")

        print(f"[+] Open ports: {self.open_ports}")

    def test_http_vulnerabilities(self):
        """
        دالة لاختبار الثغرات في HTTP مثل SQL Injection و XSS
        """
        url = f"http://{self.target}"
        print("\n[+] Testing HTTP vulnerabilities...")

        try:
            # تحسين اختبار الثغرات باستخدام `ThreadPoolExecutor` لتنفيذ عدة طلبات في وقت واحد
            response = requests.get(url, timeout=3)
            self.report += f"\n[+] HTTP Response Status: {response.status_code}\n"
            
            # فحص تمكين عرض الدليل
            if "Index of" in response.text:
                print(f"{YELLOW}[!] Directory Listing is enabled!{RESET}")
                self.report += "Directory Listing is enabled!\n"
            
            # اختبار حقن SQL (موسع)
            sql_injection_payloads = ["1' OR '1'='1", "1' UNION SELECT NULL, NULL, NULL --", "' OR 1=1 --"]
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.check_sql_injection, url, payload): payload for payload in sql_injection_payloads}
                for future in tqdm(as_completed(futures), total=len(sql_injection_payloads), desc="SQL Injection Testing"):
                    future.result()
            
            # اختبار XSS (محاكاة)
            xss_url = f"{url}?name=<script>alert('XSS')</script>"
            xss_response = requests.get(xss_url, timeout=3)
            if "<script>" in xss_response.text:
                print(f"{RED}[!] Possible XSS vulnerability!{RESET}")
                self.report += "Possible XSS vulnerability!\n"
            
        except requests.exceptions.RequestException as e:
            logging.error(f"HTTP Test Error: {e}")
            print(f"{RED}[!] HTTP Test Error: {e}{RESET}")
        except Exception as e:
            logging.error(f"Unexpected error during HTTP vulnerability testing: {e}")
            print(f"{RED}[!] Unexpected error: {e}{RESET}")

    def check_sql_injection(self, url, payload):
        """
        دالة لاختبار SQL Injection على عنوان URL
        :param url: عنوان URL لاختبار SQL Injection عليه
        :param payload: الحمولة الخاصة باختبار SQL Injection
        """
        sql_url = f"{url}?id={payload}"
        try:
            sql_response = requests.get(sql_url, timeout=3)
            if "SQL" in sql_response.text or "error" in sql_response.text.lower():
                print(f"{RED}[!] Possible SQL Injection vulnerability!{RESET}")
                self.report += "Possible SQL Injection vulnerability!\n"
        except requests.exceptions.RequestException as e:
            logging.error(f"Error testing SQL Injection for payload {payload}: {e}")
            print(f"{RED}[!] Error testing SQL Injection for payload {payload}: {e}{RESET}")
    
    def save_report(self):
        """حفظ التقرير إلى ملف"""
        try:
            with open("scan_report.txt", "w") as file:
                file.write(self.report)
            print(f"{GREEN}[+] Report saved as scan_report.txt{RESET}")
        except Exception as e:
            logging.error(f"Error saving report: {e}")
            print(f"{RED}[!] Error saving report: {e}{RESET}")

    def show_possible_vulnerabilities(self):
        """عرض الثغرات المحتملة التي قد توجد في النظام"""
        print("\n[+] Possible vulnerabilities:")
        print("- SQL Injection")
        print("- Cross-Site Scripting (XSS)")
        print("- Directory Listing")
        print("- Open Ports Exploitation")
        print("- CSRF")
        print("- RFI")
        print("- SSRF")
        print("- Cookie Security (HttpOnly, Secure)")
        self.report += "\nPossible vulnerabilities:\n- SQL Injection\n- XSS\n- Directory Listing\n- Open Ports Exploitation\n- CSRF\n- RFI\n- SSRF\n- Cookie Security\n"

    def menu(self):
        """القائمة الرئيسية مع تحسين الأداء"""
        os.system("clear")
        
        # تصميم العنوان
        print(f"{BLUE}{'='*40}{RESET}")
        print(f"{GREEN}{BOLD}         QWep-Scan Tool         {RESET}")
        print(f"{BLUE}{'='*40}{RESET}")
        print(f"\n[+] Target: {self.target} ({self.ip})")

        while True:
            print("\nChoose an option:")
            print("1. Full Port Scan (1-65535)")
            print("2. Common Port Scan (80, 443, 8080, 3306)")
            print("3. HTTP Security Tests")
            print("4. Exploit Open Ports")
            print("5. Check SSL Vulnerabilities")
            print("6. Show Possible Vulnerabilities")
            print("7. Save Report")
            print("8. Exit")
            
            choice = input("Enter your choice: ")
            if choice == "1":
                self.port_scanner(range(1, 65536))
            elif choice == "2":
                self.port_scanner([80, 443, 8080, 3306])
            elif choice == "3":
                self.test_http_vulnerabilities()
            elif choice == "4":
                if not self.open_ports:
                    print(f"{RED}[-] No open ports found. Please scan first.{RESET}")
                    continue
                self.exploit_open_ports()
            elif choice == "5":
                self.check_ssl()
            elif choice == "6":
                self.show_possible_vulnerabilities()
            elif choice == "7":
                self.save_report()
            elif choice == "8":
                print(f"{GREEN}[+] Thank you for using QWep-Scan. Goodbye!{RESET}")
                sys.exit()
            else:
                print(f"{YELLOW}[-] Invalid choice, please try again.{RESET}")

if __name__ == "__main__":
    try:
        print(f"{BLUE}{'='*40}{RESET}")
        print(f"{GREEN}{BOLD}         QWep-Scan Tool         {RESET}")
        print(f"{BLUE}{'='*40}{RESET}")
        
        target = input("\nEnter target URL or IP: ").strip()
        scanner = QWepScan(target)
        scanner.menu()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted. Goodbye!")
        sys.exit()
