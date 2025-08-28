import os

from printer import printerr, printout, printwarn

class PrintTXT:
    def __init__(self, output_dir, results, cves, start_time, end_time):
        self.output_file = os.path.join(output_dir, "reports", "report.txt")
        self.results = results
        self.cves = cves
        self.start_time = start_time
        self.end_time = end_time
        self.total_time = (end_time - start_time)
        self.output = """"""

    def start(self):
        printout("Parsing the results for report")
        self.create_output()
        printout("Results are parsed and ready to be written")
        printout("Writing results to file...")
        self.print_results()

    def print_results(self):
        try:
            with open(self.output_file, "w") as f:
                f.write(self.output)
        except IOError as e:
            printerr(f"Error for reports.txt: {e}")

    def create_output(self):
        title = """
.-------------------------------------------------------------------.
| ____   ____    _    _   _      ____  _____ ____   ___  ____ _____ |
|/ ___| / ___|  / \\  | \\ | |    |  _ \\| ____|  _ \\ / _ \\|  _ \\_   _||
|\\___ \\| |     / _ \\ |  \\| |    | |_) |  _| | |_) | | | | |_) || |  |
| ___) | |___ / ___ \\| |\\  |    |  _ <| |___|  __/| |_| |  _ < | |  |
||____/ \\____/_/   \\_\\_| \\_|    |_| \\_\\_____|_|    \\___/|_| \\_\\|_|  |
'-------------------------------------------------------------------'
"""

        disclaimer = "The results of this scan are indicative and may be inaccurate (especially for CVEs),\nfurther analysis and research is required. You should not use this script for malicious purposes!\n\n"

        info_title = """
        
.-------.
|INFOS: |
'-------'"""

        open_ports = self.results.get("0", {}).get("nmap").get("open_ports")
        info = f"""
Target IP: {self.results.get("0", {}).get("nmap").get("target_ip")}
Open Ports:
{(''.join([f'  - {port}\n' for port in open_ports]) if open_ports else '  None\n').rstrip()}
Detected OS: {self.results.get("0", {}).get("nmap").get("os")}
Type: {self.results.get("0", {}).get("nmap").get("vendor")}: {self.results.get("0", {}).get("nmap").get("family")} - {self.results.get("0", {}).get("nmap").get("type")}
MAC Address: {self.results.get("0", {}).get("nmap").get("mac")}
Scan Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
Scan Ended at: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}
Total Time: {self.total_time}
"""

        service_title = """
        
.------------------.
|SERVICE ANALYSIS: |
'------------------'"""

        self.output += title + disclaimer + info_title + info + service_title

        normalized = {int(k): v for k, v in self.results.items()}
        for port in sorted(normalized):
            data = normalized[port]

            if port == 0:
                continue

            if "nftp" in data:
                ftp_info = self.ftp_info(port, data)
                self.output += ftp_info
            elif "nssh" in data:
                ssh_info = self.ssh_info(port, data)
                self.output += ssh_info
            elif "nsmtp" in data:
                smtp_info = self.smtp_info(port, data)
                self.output += smtp_info
            elif "dig" in data:
                dns_info = self.dns_info(port, data)
                self.output += dns_info
            elif "nsmb" in data:
                smb_info = self.smb_info(port, data)
                self.output += smb_info
            elif "nhttp" in data:
                http_info = self.http_info(port, data)
                self.output += http_info
                if "sslscan" in data:
                    ssl_info = self.ssl_info(data)
                    self.output += ssl_info
                self.output += "\n"
                if "wpscan" in data:
                    wpscan_info = self.wpscan_info(data)
                    self.output += wpscan_info
            elif data:
                self.output += f"\n{"-" * 30}\n(Port {port})\n  No service found for port {port}, data is founded\n  This is an error, please report it to the author\n"
            else:
                self.output += f"\n{"-" * 30}\n(Port {port})\n  No service found for port {port}\n  If you think this is an error please report it to the author\n"

        cves_title = """
        
.---------------.
|CVEs ANALYSIS: |
'---------------'"""
        self.output += cves_title
        if self.cves:
            self.output += self.cve_info()
        else:
            self.output += "No CVEs found"


    @staticmethod
    def ftp_info(port, data):
        title = f"""FTP (Port {port})"""
        product = data.get("nftp", {}).get("product")
        version = data.get("nftp", {}).get("version")
        extra_info = data.get("nftp", {}).get("extrainfo")
        anon_login = data.get("aftp", {}).get("anonymous_login")
        credentials = "\n".join(f"    - {creds['login']}:{creds['password']}" for creds in data.get("hydra", []))
        directories = data.get("nftp", {}).get("directory_listing")
        bounce = data.get("nftp", {}).get("ftp_bounce_vulnerable")
        proftpd_bd = data.get("nftp", {}).get("proftpd_backdoor")
        vsftpd_bd = data.get("nftp", {}).get("vsftpd_backdoor")
        vuln_cve2010_4221 = data.get("nftp", {}).get("ftp_vuln_cve2010_4221") if data.get("nftp", {}).get("ftp_vuln_cve2010_4221") else "False"
        vuln_cve2010_1938 = data.get("nftp", {}).get("ftp_vuln_cve2010_1938") if data.get("nftp", {}).get("ftp_vuln_cve2010_1938") else "False"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Extra Info: {extra_info}
  Anonymous Login: {anon_login}
  Credentials: 
{credentials}
  Directory Listing: {directories}
  FTP Bounce: {bounce}
  ProFTPD Backdoor: {proftpd_bd}
  VSFTPD Backdoor: {vsftpd_bd}
  CVE-2010-4221: {vuln_cve2010_4221}
  CVE-2010-1938: {vuln_cve2010_1938}
"""

    @staticmethod
    def ssh_info(port, data):
        title = f"""SSH (Port {port})"""
        product = data.get("nssh", {}).get("product")
        version = data.get("nssh", {}).get("version")
        protocol = data.get("ssh-audit", {}).get("protocol")
        extra_info = data.get("nssh", {}).get("extrainfo")
        pubkey_acceptance = data.get("nssh", {}).get("publickey_acceptance")
        cves = data.get("ssh-audit", {}).get("cves") if data.get("ssh-audit", {}).get("cves") else "No CVEs found"
        algorithms = ""

        for alg, data in data.get("ssh-audit", {}).items():
            if alg not in ["protocol", "software", "cves"]:
                description = ""
                fail = data.get("fail")
                warn = data.get("warn")

                if data['fail'] and isinstance(fail, list):
                    fail = "; ".join(fail)
                    description += f"{fail}; "
                if data['warn'] and isinstance(warn, list):
                    warn = "; ".join(warn)
                    description += f"{warn};"
                algorithms += f"    - {alg}: {description}\n"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Protocol: {protocol}
  Extra Info: {extra_info}
  Public Key Acceptance: {pubkey_acceptance}
  SA CVEs: {cves}
  Weak Algorithms: 
{algorithms}"""

    @staticmethod
    def smtp_info(port, data):
        title = f"""SMTP (Port {port})"""
        product = data.get("nsmtp", {}).get("product")
        version = data.get("nsmtp", {}).get("version")
        extra_info = data.get("nsmtp", {}).get("extrainfo")
        smtp_commands = ""
        open_relay = data.get("nsmtp", {}).get("open_relay")
        enum_users = data.get("nsmtp", {}).get("enum_users")
        vuln_cve2010_4344 = data.get("nsmtp", {}).get("vuln_cve2010_4344")

        for command in data.get("nsmtp", {}).get("smtp_commands"):
            smtp_commands += f"    - {command}\n"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Extra Info: {extra_info}
  SMTP Commands: 
{smtp_commands}
  Open Relay: {open_relay}
  Enum Users: {enum_users}
  CVE-2010-4344: {vuln_cve2010_4344}
  """

    @staticmethod
    def dns_info(port, data):
        title = f"""DNS (Port {port})"""

        information_disclosure = False
        open_resolver = False
        amplification = False

        for item in data.get("dig", []):
            if item.get("vulnerability_type") == "information_disclosure":
                information_disclosure = True
            if item.get("vulnerability_type") == "open_resolver":
                open_resolver = True
            if item.get("vulnerability_type") == "amplification":
                amplification = True


        return f"""
{"-" * 30}
{title}
  Information Disclosure: {information_disclosure}
  Open Resolver: {open_resolver}
  Amplification: {amplification}
  """

    @staticmethod
    def smb_info(port, data):
        title = f"""SMB (Port {port})"""
        product = data.get("nsmb", {}).get("product")
        version = data.get("nsmb", {}).get("version")
        dialects = ""
        vuln_ms10_054 = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-ms10-054")
        vuln_regsvc_dos = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-regsvc-dos")
        vuln_ms10_061 = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-ms10-061")
        users = ""
        pass_length = data.get("enum4linux", {}).get("policy", {}).get("min_password_length") if data.get("enum4linux", {}).get("policy", {}).get("min_password_length") else "Unknown"
        pass_complex = data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_COMPLEX") if data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_COMPLEX") else "Unknown"
        pass_cleartext = data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT") if data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT") else "False"

        for uuid, user in data.get("enum4linux", {}).get("users", {}).items():
            users += f"    - {user}\n"

        for dialect in data.get("nsmb", {}).get("dialects"):
            dialects += f"    - {dialect}\n"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Dialects: 
{dialects}
  Vulnerable To MS10-054: {vuln_ms10_054}
  Vulnerable To REGSVR32: {vuln_regsvc_dos}
  Vulnerable To MS10-061: {vuln_ms10_061}
  Users: 
{users}
  Min Password Length Required: {pass_length}
  Password Complexity Required: {pass_complex}
  Password Stored In Cleartext: {pass_cleartext}
  """

    @staticmethod
    def http_info(port, data):
        title = f"""HTTP (Port {port})"""
        website_title = data.get("nhttp", {}).get("http-title")
        git_url = data.get("nhttp", {}).get("http-git", {}).get("url")
        git_type = data.get("nhttp", {}).get("http-git", {}).get("type")
        robots = ""
        auth = ""
        methods = ""
        waf = data.get("nhttp", {}).get("http_waf_detect")
        open_proxy = data.get("nhttp", {}).get("http_open_proxy")
        nikto_msg = ""
        paths = ""

        for path in data.get("nhttp", {}).get("http_robots"):
            robots += f"    - {path}\n"
        for url in data.get("nhttp", {}).get("http_auth_finder"):
            auth += f"    - {url}\n"
        for i in data.get("nikto", []):
            nikto_msg += f"    - {i.get("msg")}\n"
        for method in data.get("nhttp", []).get("http-methods", []):
            methods += f"    - {method}\n"

        ffuf_2 = []
        ffuf_3 = []
        ffuf_4 = []
        for item in data.get("ffuf", []):
            if item.get("status") in [200, 204]:
                ffuf_2.append(f"{item.get("status")}: {item.get("url")} ")
            elif item.get("status") in [301, 302, 307]:
                ffuf_3.append(f"{item.get("status")}: {item.get("url")}")
            elif item.get("status") == 401:
                ffuf_4.append(f"{item.get("status")}: {item.get("url")}")
            else:
                printwarn(f"Unhandled status code: {item.get("status")}, ignoring")

        for path in ffuf_2:
            paths += f"    - {path}\n"
        for path in ffuf_3:
            paths += f"    - {path}\n"
        for path in ffuf_4:
            paths += f"    - {path}\n"

        return f"""
{"-" * 30}
{title}
  Website Title: {website_title}
  Login URLs: 
{auth}
  Git Project URL: {git_url}
  Git Project Type: {git_type}
  Hidden Directories (Robots.txt): 
{robots if robots else "None"}
  Accepted Risky Methods: 
{methods if methods else "None"}
  Web Application Firewall ON: {waf}
  Open Proxy: {open_proxy}
  Warnings Messages: 
{nikto_msg}
  Found Paths: 
{paths}
  """

    @staticmethod
    def ssl_info(data):
        protocols = data.get("sslscan", {}).get("protocols")
        ciphers_weak = data.get("sslscan", {}).get("ciphers", {}).get("weak")
        ciphers_insecure = data.get("sslscan", {}).get("ciphers", {}).get("insecure")
        cert_expired = data.get("sslscan", {}).get("certificate", {}).get("expired")
        cert_self_signed = data.get("sslscan", {}).get("certificate", {}).get("self_signed")
        cert_short_key = data.get("sslscan", {}).get("certificate", {}).get("short_key")

        return f"""  SSL Protocols: {protocols}
  Weak Ciphers: {ciphers_weak}
  Insecure Ciphers: {ciphers_insecure}
  Certificate Expired: {cert_expired}
  Certificate Self Signed: {cert_self_signed}
  Certificate Short Key: {cert_short_key}
  """

    @staticmethod
    def wpscan_info(data):
        version = data.get("version")
        release = data.get("release")
        secure = data.get("secure")
        users = ""
        found_urls = ""
        wp_vulnerabilities = ""
        plugins = ""
        main_theme = ""
        themes = ""


        for user in data.get("users", []):
            users += f"    - {user}\n"

        for url in data.get("interesting_findings", []):
            found_urls += f"    - {url}\n"
        for wp_vulnerability in data.get("vulnerabilities", []):
            wp_vulnerabilities += f"    - {f"CVE-{wp_vulnerability.get("cve")}:" if wp_vulnerability.get("cve") else ""}{wp_vulnerability.get("title")}\n"

        for plugin, info in data.get("plugins", []):
            plugins += f"    - {plugin}: {info.get("version")}\n"
            plugins += f"        - Outdated: {info.get("outdated")}\n"
            plugins += f"        - Latest Version: {info.get("latest_version")}\n"
            plugins += f"        - Vulnerabilities:\n"
            for cve in info.get("vulnerabilities", []):
                plugins += f"          - {f"CVE-{cve.get("cve")}:" if cve.get("cve") else ""}{cve.get("title")}\n"

        for info in data.get("main_theme", []):
            main_theme += f"    Theme Name: {info.get("name")}: {info.get("version")}\n"
            main_theme += f"    Outdated: {info.get("outdated")}\n"
            main_theme += f"    Latest Version: {info.get("latest_version")}\n"
            main_theme += f"    Vulnerabilities:\n"
            for cve in info.get("vulnerabilities", []):
                main_theme += f"      - {f"CVE-{cve.get("cve")}:" if cve.get("cve") else ""}{cve.get("title")}\n"

        for theme in data.get("themes", []):
            themes += f"    - {theme.get("name")}\n"
            themes += f"        Version: {theme.get("version")}\n"
            themes += f"        Outdated: {theme.get("outdated")}\n"
            themes += f"        Latest Version: {theme.get("latest_version")}\n"
            themes += f"        Vulnerabilities:\n"
            for cve in theme.get("vulnerabilities", []):
                themes += f"        - {f"CVE-{cve.get("cve")}:" if cve.get("cve") else ""}{cve.get("title")}\n"

        if themes == "":
            themes = "    No other theme founded"

        return  f"""  Wordpress Version: {version} - {release}
  Secure: {secure}
  Founded Usernames: 
{users}
  Founded Special URLs: 
{found_urls}
  Wordpress Vulnerabilities: 
{wp_vulnerabilities}
  Plugins: 
{plugins}
  Main Theme: 
{main_theme}
  Other Themes:
{themes}
  """

    def cve_info(self):
        output = ""

        cves = self.cves.get("cves", [])
        stats = self.cves.get("statistics", {})

        output += "\n"
        output += f"CVEs Found: {stats.get("cves_found")}\n"
        output += f"CVSS Medium: {stats.get("cvss_medium")}  (calculated with available data)\n"
        output += f"Errors: {stats.get("errors")}\n"
        output += "\n"

        for cve in cves:
            output += "\n"
            output += f"CVE ID: {cve.get("cve_id")}\n"
            output += f"  - PRODUCT: {cve.get("vendor")}:{cve.get("product")} {cve.get("version")}\n"
            output += f"  - SUMMARY: {cve.get("summary").replace("\n", " ")}\n" if cve.get("summary") else "  - SUMMARY: N/A\n"
            output += f"  - CVSS SCORE: {cve.get("cvss_score")}" if cve.get("cvss_score") else "  - CVSS SCORE: N/A"
            output += f" -> {cve.get("severity")}\n" if cve.get("severity") else "\n"
            #output += f"  - PUBLISHED ON: {cve.get("published")}\n" if cve.get("published") else "  - PUBLISHED ON: N/A\n"

        return output