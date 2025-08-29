import os

from printer import printerr, printout, printwarn


class PrintTXT:
    def __init__(self, output_dir, results, cves, start_time, end_time):
        self.output_file = os.path.join(output_dir, "reports", "report.txt")
        self.results = results if isinstance(results, dict) else {}
        self.cves = cves if isinstance(cves, dict) else {}
        self.start_time = start_time
        self.end_time = end_time
        self.total_time = (end_time - start_time)
        self.output = """"""

    def start(self):
        printout("Parsing the results for report")

        # Create reports directory if it doesn't exist
        reports_dir = os.path.dirname(self.output_file)
        if not os.path.exists(reports_dir):
            try:
                os.makedirs(reports_dir, exist_ok=True)
            except OSError as e:
                printerr(f"Error creating reports directory: {e}")
                return

        self.create_output()
        printout("Results are parsed and ready to be written")
        printout("Writing results to file...")
        self.print_results()

    def print_results(self):
        try:
            with open(self.output_file, "w", encoding='utf-8') as f:
                f.write(self.output)
            printout(f"Report written successfully to {self.output_file}")
        except IOError as e:
            printerr(f"Error writing report.txt: {e}")

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

        # Safe access to nmap data
        nmap_data = self.results.get("0", {}).get("nmap", {})
        open_ports = nmap_data.get("open_ports", [])

        # Format open ports safely
        open_ports_str = ""
        if isinstance(open_ports, list) and open_ports:
            for port in open_ports:
                open_ports_str += f"  - {port}\n"
        else:
            open_ports_str = "  None\n"

        info = f"""
Target IP: {nmap_data.get("target_ip", "Unknown")}
Open Ports:
{open_ports_str.rstrip()}
Detected OS: {nmap_data.get("os", "Unknown")}
Type: {nmap_data.get("vendor", "Unknown")}: {nmap_data.get("family", "Unknown")} - {nmap_data.get("type", "Unknown")}
MAC Address: {nmap_data.get("mac", "Unknown")}
Scan Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'Unknown'}
Scan Ended at: {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'Unknown'}
Total Time: {self.total_time if self.total_time else 'Unknown'}
"""

        service_title = """

.------------------.
|SERVICE ANALYSIS: |
'------------------'"""

        self.output += title + disclaimer + info_title + info + service_title

        # Convert keys to integers safely and sort
        normalized = {}
        for k, v in self.results.items():
            try:
                normalized[int(k)] = v
            except (ValueError, TypeError):
                printerr(f"Invalid port key: {k}")
                continue

        for port in sorted(normalized.keys()):
            data = normalized[port]
            if not isinstance(data, dict):
                continue

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
                self.output += f"\n{"-" * 30}\n(Port {port})\n  No service found for port {port}, data is found\n  This is an error, please report it to the author\n"
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
            self.output += "\nNo CVEs found\n"

    @staticmethod
    def ftp_info(port, data):
        title = f"""FTP (Port {port})"""

        nftp_data = data.get("nftp", {})
        aftp_data = data.get("aftp", {})
        hydra_data = data.get("hydra", [])

        product = nftp_data.get("product", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        version = nftp_data.get("version", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        extra_info = nftp_data.get("extrainfo", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        anon_login = aftp_data.get("anonymous_login", "Unknown") if isinstance(aftp_data, dict) else "Unknown"

        credentials = ""
        if isinstance(hydra_data, list):
            for creds in hydra_data:
                if isinstance(creds, dict):
                    login = creds.get('login', '')
                    password = creds.get('password', '')
                    credentials += f"    - {login}:{password}\n"
        if not credentials:
            credentials = "    None\n"

        directories = nftp_data.get("directory_listing", "None") if isinstance(nftp_data, dict) else "None"
        bounce = nftp_data.get("ftp_bounce_vulnerable", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        proftpd_bd = nftp_data.get("proftpd_backdoor", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        vsftpd_bd = nftp_data.get("vsftpd_backdoor", "Unknown") if isinstance(nftp_data, dict) else "Unknown"
        vuln_cve2010_4221 = nftp_data.get("ftp_vuln_cve2010_4221", "False") if isinstance(nftp_data, dict) else "False"
        vuln_cve2010_1938 = nftp_data.get("ftp_vuln_cve2010_1938", "False") if isinstance(nftp_data, dict) else "False"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Extra Info: {extra_info}
  Anonymous Login: {anon_login}
  Credentials: 
{credentials.rstrip()}
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

        nssh_data = data.get("nssh", {})
        ssh_audit_data = data.get("ssh-audit", {})

        product = nssh_data.get("product", "Unknown") if isinstance(nssh_data, dict) else "Unknown"
        version = nssh_data.get("version", "Unknown") if isinstance(nssh_data, dict) else "Unknown"
        protocol = ssh_audit_data.get("protocol", "Unknown") if isinstance(ssh_audit_data, dict) else "Unknown"
        extra_info = nssh_data.get("extrainfo", "Unknown") if isinstance(nssh_data, dict) else "Unknown"
        pubkey_acceptance = nssh_data.get("publickey_acceptance", "Unknown") if isinstance(nssh_data,
                                                                                           dict) else "Unknown"

        cves = "No CVEs found"
        if isinstance(ssh_audit_data, dict) and ssh_audit_data.get("cves"):
            cves = ssh_audit_data.get("cves")

        algorithms = ""
        if isinstance(ssh_audit_data, dict):
            for alg, alg_data in ssh_audit_data.items():
                if alg not in ["protocol", "software", "cves"] and isinstance(alg_data, dict):
                    description = ""
                    fail = alg_data.get("fail")
                    warn = alg_data.get("warn")

                    if fail and isinstance(fail, list):
                        fail_str = "; ".join(str(f) for f in fail)
                        description += f"{fail_str}; "
                    elif fail:
                        description += f"{fail}; "

                    if warn and isinstance(warn, list):
                        warn_str = "; ".join(str(w) for w in warn)
                        description += f"{warn_str};"
                    elif warn:
                        description += f"{warn};"

                    if description:
                        algorithms += f"    - {alg}: {description}\n"

        if not algorithms:
            algorithms = "    None found\n"

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
{algorithms.rstrip()}"""

    @staticmethod
    def smtp_info(port, data):
        title = f"""SMTP (Port {port})"""

        nsmtp_data = data.get("nsmtp", {})

        product = nsmtp_data.get("product", "Unknown") if isinstance(nsmtp_data, dict) else "Unknown"
        version = nsmtp_data.get("version", "Unknown") if isinstance(nsmtp_data, dict) else "Unknown"
        extra_info = nsmtp_data.get("extrainfo", "Unknown") if isinstance(nsmtp_data, dict) else "Unknown"
        open_relay = nsmtp_data.get("open_relay", "Unknown") if isinstance(nsmtp_data, dict) else "Unknown"
        enum_users = nsmtp_data.get("enum_users", "None") if isinstance(nsmtp_data, dict) else "None"
        vuln_cve2010_4344 = nsmtp_data.get("vuln_cve2010_4344", "Unknown") if isinstance(nsmtp_data,
                                                                                         dict) else "Unknown"

        smtp_commands = ""
        if isinstance(nsmtp_data, dict):
            commands = nsmtp_data.get("smtp_commands")
            if isinstance(commands, list):
                for command in commands:
                    smtp_commands += f"    - {command}\n"
            else:
                smtp_commands = "    None\n"
        else:
            smtp_commands = "    Unknown\n"

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Extra Info: {extra_info}
  SMTP Commands: 
{smtp_commands.rstrip()}
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

        dig_data = data.get("dig", [])
        if isinstance(dig_data, list):
            for item in dig_data:
                if isinstance(item, dict):
                    vuln_type = item.get("vulnerability_type")
                    if vuln_type == "information_disclosure":
                        information_disclosure = True
                    elif vuln_type == "open_resolver":
                        open_resolver = True
                    elif vuln_type == "amplification":
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

        nsmb_data = data.get("nsmb", {})
        enum4linux_data = data.get("enum4linux", {})

        product = nsmb_data.get("product", "Unknown") if isinstance(nsmb_data, dict) else "Unknown"
        version = nsmb_data.get("version", "Unknown") if isinstance(nsmb_data, dict) else "Unknown"

        dialects = ""
        if isinstance(nsmb_data, dict):
            dialects_list = nsmb_data.get("dialects", [])
            if isinstance(dialects_list, list):
                for dialect in dialects_list:
                    dialects += f"    - {dialect}\n"
            else:
                dialects = "    Unknown\n"
        else:
            dialects = "    Unknown\n"

        # Handle vulnerabilities safely
        vulnerabilities = nsmb_data.get("vulnerabilities", {}) if isinstance(nsmb_data, dict) else {}
        vuln_ms10_054 = "Unknown"
        vuln_regsvc_dos = "Unknown"
        vuln_ms10_061 = "Unknown"

        if isinstance(vulnerabilities, dict):
            vuln_ms10_054 = vulnerabilities.get("smb-vuln-ms10-054", "Unknown")
            vuln_regsvc_dos = vulnerabilities.get("smb-vuln-regsvc-dos", "Unknown")
            vuln_ms10_061 = vulnerabilities.get("smb-vuln-ms10-061", "Unknown")

        users = ""
        if isinstance(enum4linux_data, dict):
            users_dict = enum4linux_data.get("users", {})
            if isinstance(users_dict, dict):
                for user_id, user in users_dict.items():
                    users += f"    - {user}\n"
            else:
                users = "    None found\n"
        else:
            users = "    Unknown\n"

        # Handle policy safely
        pass_length = "Unknown"
        pass_complex = "Unknown"
        pass_cleartext = "Unknown"

        if isinstance(enum4linux_data, dict):
            policy = enum4linux_data.get("policy", {})
            if isinstance(policy, dict):
                pass_length = policy.get("min_password_length", "Unknown")
                pass_complex = policy.get("DOMAIN_PASSWORD_COMPLEX", "Unknown")
                pass_cleartext = policy.get("DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT", "Unknown")

        return f"""
{"-" * 30}
{title}
  Product: {product}
  Version: {version}
  Dialects: 
{dialects.rstrip()}
  Vulnerable To MS10-054: {vuln_ms10_054}
  Vulnerable To REGSVR32: {vuln_regsvc_dos}
  Vulnerable To MS10-061: {vuln_ms10_061}
  Users: 
{users.rstrip()}
  Min Password Length Required: {pass_length}
  Password Complexity Required: {pass_complex}
  Password Stored In Cleartext: {pass_cleartext}
  """

    @staticmethod
    def http_info(port, data):
        title = f"""HTTP (Port {port})"""

        nhttp_data = data.get("nhttp", {})
        nikto_data = data.get("nikto", [])
        ffuf_data = data.get("ffuf", [])

        website_title = "Unknown"
        git_url = "None"
        git_type = "None"
        waf = False
        open_proxy = False

        if isinstance(nhttp_data, dict):
            website_title = nhttp_data.get("http_title", "Unknown")

            git_info = nhttp_data.get("http_git", {})
            if isinstance(git_info, dict):
                git_url = git_info.get("url", "None")
                git_type = git_info.get("type", "None")
            elif not git_info:
                git_url = "None"
                git_type = "None"

            waf = nhttp_data.get("http_waf_detect", False)
            open_proxy = nhttp_data.get("http_open_proxy", False)

        robots = ""
        if isinstance(nhttp_data, dict):
            http_robots = nhttp_data.get("http_robots")
            if isinstance(http_robots, list):
                for path in http_robots:
                    robots += f"    - {path}\n"
            else:
                robots = "    None\n"
        else:
            robots = "    Unknown\n"

        auth = ""
        if isinstance(nhttp_data, dict):
            http_auth_finder = nhttp_data.get("http_auth_finder")
            if isinstance(http_auth_finder, list):
                for url in http_auth_finder:
                    auth += f"    - {url}\n"
            else:
                auth = "    None\n"
        else:
            auth = "    Unknown\n"

        methods = ""
        if isinstance(nhttp_data, dict):
            http_methods = nhttp_data.get("http_methods")
            if isinstance(http_methods, list):
                for method in http_methods:
                    methods += f"    - {method}\n"
            elif isinstance(http_methods, str):
                methods = f"    {http_methods}\n"
            else:
                methods = "    None\n"
        else:
            methods = "    Unknown\n"

        nikto_msg = ""
        if isinstance(nikto_data, list):
            for i in nikto_data:
                if isinstance(i, dict):
                    msg = i.get("msg", "")
                    nikto_msg += f"    - {msg}\n"
        if not nikto_msg:
            nikto_msg = "    None\n"

        paths = ""
        ffuf_2 = []
        ffuf_3 = []
        ffuf_4 = []

        if isinstance(ffuf_data, list):
            for item in ffuf_data:
                if isinstance(item, dict):
                    status = item.get("status")
                    url = item.get("url", "")

                    if status in [200, 204]:
                        ffuf_2.append(f"{status}: {url}")
                    elif status in [301, 302, 307]:
                        ffuf_3.append(f"{status}: {url}")
                    elif status == 401:
                        ffuf_4.append(f"{status}: {url}")
                    elif status is not None:
                        printwarn(f"Unhandled status code: {status}, ignoring")

        for path in ffuf_2 + ffuf_3 + ffuf_4:
            paths += f"    - {path}\n"
        if not paths:
            paths = "    None\n"

        return f"""
{"-" * 30}
{title}
  Website Title: {website_title}
  Login URLs: 
{auth.rstrip()}
  Git Project URL: {git_url}
  Git Project Type: {git_type}
  Hidden Directories (Robots.txt): 
{robots.rstrip()}
  Accepted Risky Methods: 
{methods.rstrip()}
  Web Application Firewall ON: {waf}
  Open Proxy: {open_proxy}
  Warning Messages: 
{nikto_msg.rstrip()}
  Found Paths: 
{paths.rstrip()}
  """

    @staticmethod
    def ssl_info(data):
        sslscan_data = data.get("sslscan", {})

        protocols = "None"
        ciphers_weak = "None"
        ciphers_insecure = "None"
        cert_expired = "Unknown"
        cert_self_signed = "Unknown"
        cert_short_key = "Unknown"

        if isinstance(sslscan_data, dict):
            protocols = sslscan_data.get("protocols", "None")

            ciphers = sslscan_data.get("ciphers", {})
            if isinstance(ciphers, dict):
                ciphers_weak = ciphers.get("weak", "None")
                ciphers_insecure = ciphers.get("insecure", "None")

            certificate = sslscan_data.get("certificate", {})
            if isinstance(certificate, dict):
                cert_expired = certificate.get("expired", "Unknown")
                cert_self_signed = certificate.get("self_signed", "Unknown")
                cert_short_key = certificate.get("short_key", "Unknown")

        return f"""  SSL Protocols: {protocols}
  Weak Ciphers: {ciphers_weak}
  Insecure Ciphers: {ciphers_insecure}
  Certificate Expired: {cert_expired}
  Certificate Self Signed: {cert_self_signed}
  Certificate Short Key: {cert_short_key}
  """

    @staticmethod
    def wpscan_info(data):
        wpscan_data = data.get("wpscan", {})
        if not isinstance(wpscan_data, dict):
            return "  WordPress scan data not available\n"

        version = wpscan_data.get("version", "Unknown")
        release = wpscan_data.get("release", "Unknown")
        secure = wpscan_data.get("secure", "Unknown")

        users = ""
        users_list = wpscan_data.get("users", [])
        if isinstance(users_list, list):
            for user in users_list:
                users += f"    - {user}\n"
        if not users:
            users = "    None\n"

        found_urls = ""
        interesting_findings = wpscan_data.get("interesting_findings", [])
        if isinstance(interesting_findings, list):
            for url in interesting_findings:
                found_urls += f"    - {url}\n"
        if not found_urls:
            found_urls = "    None\n"

        wp_vulnerabilities = ""
        vulnerabilities = wpscan_data.get("vulnerabilities", [])
        if isinstance(vulnerabilities, list):
            for wp_vulnerability in vulnerabilities:
                if isinstance(wp_vulnerability, dict):
                    title = wp_vulnerability.get("title", "")
                    cve = wp_vulnerability.get("cve", "")
                    cve_prefix = f"CVE-{cve}:" if cve else ""
                    wp_vulnerabilities += f"    - {cve_prefix}{title}\n"
        if not wp_vulnerabilities:
            wp_vulnerabilities = "    None\n"

        plugins = ""
        plugins_dict = wpscan_data.get("plugins", {})
        if isinstance(plugins_dict, dict):
            for plugin, info in plugins_dict.items():
                if isinstance(info, dict):
                    plugins += f"    - {plugin}: {info.get('version', 'Unknown')}\n"
                    plugins += f"        - Outdated: {info.get('outdated', 'Unknown')}\n"
                    plugins += f"        - Latest Version: {info.get('latest_version', 'Unknown')}\n"
                    plugins += f"        - Vulnerabilities:\n"

                    plugin_vulns = info.get("vulnerabilities", [])
                    if isinstance(plugin_vulns, list):
                        for cve in plugin_vulns:
                            if isinstance(cve, dict):
                                title = cve.get("title", "")
                                cve_id = cve.get("cve", "")
                                cve_prefix = f"CVE-{cve_id}:" if cve_id else ""
                                plugins += f"          - {cve_prefix}{title}\n"
                    else:
                        plugins += "          - None\n"
        if not plugins:
            plugins = "    None\n"

        main_theme = ""
        main_theme_data = wpscan_data.get("main_theme", {})
        if isinstance(main_theme_data, dict):
            main_theme += f"    Theme Name: {main_theme_data.get('name', 'Unknown')}: {main_theme_data.get('version', 'Unknown')}\n"
            main_theme += f"    Outdated: {main_theme_data.get('outdated', 'Unknown')}\n"
            main_theme += f"    Latest Version: {main_theme_data.get('latest_version', 'Unknown')}\n"
            main_theme += f"    Vulnerabilities:\n"

            theme_vulns = main_theme_data.get("vulnerabilities", [])
            if isinstance(theme_vulns, list):
                for cve in theme_vulns:
                    if isinstance(cve, dict):
                        title = cve.get("title", "")
                        cve_id = cve.get("cve", "")
                        cve_prefix = f"CVE-{cve_id}:" if cve_id else ""
                        main_theme += f"      - {cve_prefix}{title}\n"
            else:
                main_theme += "      - None\n"
        else:
            main_theme = "    No main theme data\n"

        themes = ""
        themes_dict = wpscan_data.get("themes", {})
        if isinstance(themes_dict, dict) and themes_dict:
            for theme_slug, theme_data in themes_dict.items():
                if isinstance(theme_data, dict):
                    themes += f"    - {theme_slug}\n"
                    themes += f"        Version: {theme_data.get('version', 'Unknown')}\n"
                    themes += f"        Outdated: {theme_data.get('outdated', 'Unknown')}\n"
                    themes += f"        Latest Version: {theme_data.get('latest_version', 'Unknown')}\n"
                    themes += f"        Vulnerabilities:\n"

                    theme_vulns = theme_data.get("vulnerabilities", [])
                    if isinstance(theme_vulns, list):
                        for cve in theme_vulns:
                            if isinstance(cve, dict):
                                title = cve.get("title", "")
                                cve_id = cve.get("cve", "")
                                cve_prefix = f"CVE-{cve_id}:" if cve_id else ""
                                themes += f"        - {cve_prefix}{title}\n"
                    else:
                        themes += "        - None\n"
        else:
            themes = "    No other themes found\n"

        return f"""  WordPress Version: {version} - {release}
  Secure: {secure}
  Found Usernames: 
{users.rstrip()}
  Found Special URLs: 
{found_urls.rstrip()}
  WordPress Vulnerabilities: 
{wp_vulnerabilities.rstrip()}
  Plugins: 
{plugins.rstrip()}
  Main Theme: 
{main_theme.rstrip()}
  Other Themes:
{themes.rstrip()}
  """

    def cve_info(self):
        output = ""

        if not isinstance(self.cves, dict):
            return "\nNo CVE data available\n"

        cves = self.cves.get("cves", [])
        stats = self.cves.get("statistics", {})

        output += "\n"
        output += f"CVEs Found: {stats.get('cves_found', 'Unknown')}\n"
        output += f"CVSS Medium: {stats.get('cvss_medium', 'Unknown')}  (calculated with available data)\n"
        output += f"Errors: {stats.get('errors', 'Unknown')}\n"
        output += "\n"

        if isinstance(cves, list):
            for cve in cves:
                if isinstance(cve, dict):
                    output += "\n"
                    output += f"CVE ID: {cve.get('cve_id', 'Unknown')}\n"

                    vendor = cve.get("vendor", "Unknown")
                    product = cve.get("product", "Unknown")
                    version = cve.get("version", "Unknown")
                    output += f"  - PRODUCT: {vendor}:{product} {version}\n"

                    summary = cve.get("summary", "")
                    if summary and isinstance(summary, str):
                        summary_clean = summary.replace("\n", " ").strip()
                        output += f"  - SUMMARY: {summary_clean}\n"
                    else:
                        output += "  - SUMMARY: N/A\n"

                    cvss_score = cve.get("cvss_score", "")
                    severity = cve.get("severity", "")
                    if cvss_score:
                        output += f"  - CVSS SCORE: {cvss_score}"
                        if severity:
                            output += f" -> {severity}\n"
                        else:
                            output += "\n"
                    else:
                        output += "  - CVSS SCORE: N/A\n"
        else:
            output += "No CVE data available\n"

        return output