# QWep-Scan: A Comprehensive Web Security Scanner

QWep-Scan is a versatile and powerful web security scanning tool designed to identify common vulnerabilities in websites and web applications. It offers a range of features that help security professionals, penetration testers, and developers identify weaknesses and potential security risks in their web assets. 

## Key Features:
- **Port Scanning**: Scans a wide range of ports to identify open and vulnerable ports.
- **HTTP Security Tests**: Tests for common HTTP vulnerabilities such as SQL Injection, XSS, CSRF, RFI, and SSRF.
- **Exploit Open Ports**: Simulates attacks on open ports, including HTTP attacks.
- **Cookie Security Check**: Checks for secure cookies with the HttpOnly and Secure flags.
- **Vulnerability Reports**: Generates detailed reports summarizing the findings and suggesting potential fixes.
- **User-Friendly Interface**: The tool includes a command-line interface with a menu for easy navigation.

## Supported Vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Remote File Inclusion (RFI)
- Server-Side Request Forgery (SSRF)
- Directory Listing
- Cookie Security (HttpOnly and Secure flags)

## Requirements:
- Python 3.x
- `requests` library (for HTTP requests)
- `tqdm` library (for progress bars)
- `socket` library (for port scanning)

## How to Use:
1. Clone the repository:  
   `git clone https://github.com/yourusername/QWep-Scan.git`
2. Install the necessary dependencies:  
   `pip install -r requirements.txt`
3. Run the tool:  
   `python qw_scan.py`
4. Choose options from the interactive menu to start scanning and testing for vulnerabilities.

## Contributing:
Feel free to fork the repository, create pull requests, or report issues. Contributions are always welcome!

## License:
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer:
This tool is intended for ethical use and security testing with the permission of the website or system owner. Unauthorized use may be illegal.

---

Feel free to explore, contribute, and improve the tool. Happy scanning!
