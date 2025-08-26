import os

from printer import printerr, printout, printwarn

class PrintTXT:
    def __init__(self, output_dir, results, cves, start_time, end_time):
        self.output_file = os.path.join(output_dir, "reports", "report.txt")
        self.results = results
        self.cves = cves
        self.start_time = start_time
        self.end_time = end_time
        self.total_time = end_time - start_time
        self.output = """"""

    def start(self):
        printout("Parsing the results for report")
        self.create_output()
        printout("Results are parsed and ready to be written")
        printout("Writing results to file")
        self.print_results()

    def print_results(self):
        try:
            with open(self.output_file, "w") as f:
                f.write(self.output)
        except IOError as e:
            printerr(f"Error for reports.txt: {e}")

    def create_output(self):
        title =  """.-------------------------------------------------------------------.
                    | ____   ____    _    _   _      ____  _____ ____   ___  ____ _____ |
                    |/ ___| / ___|  / \\  | \\ | |    |  _ \| ____|  _ \\ / _ \|  _ \_   _||
                    |\___ \| |     / _ \\ |  \| |    | |_) |  _| | |_) | | | | |_) || |  |
                    | ___) | |___ / ___ \| |\\  |    |  _ <| |___|  __/| |_| |  _ < | |  |
                    ||____/ \____/_/   \_\_| \_|    |_| \_\_____|_|    \___/|_| \_\|_|  |
                    '-------------------------------------------------------------------'
                \n\n\n"""

        disclaimer = "The results of this scan are indicative and may be inaccurate, further analysis is required. You should not use this script for malicious purposes.\n\n\n"

        info = f"""
                Target IP: {self.results.get("0", {}).get("nmap").get("target_ip")}
                Open Ports: {self.results.get("0", {}).get("nmap").get("open_ports")}
                Detected OS: {self.results.get("0", {}).get("nmap").get("os")}
                Type: {self.results.get("0", {}).get("nmap").get("vendor")}:{self.results.get("0", {}).get("nmap").get("family")} - {self.results.get("0", {}).get("nmap").get("type")}
                MAC Address: {self.results.get("0", {}).get("nmap").get("mac")}
                """

        self.output += title + info + disclaimer

        for port, data in self.results.items():
            if "nftp" in data:
                ftp_info = self.ftp_info(port, data)
                self.output += ftp_info
            if "nssh" in data:
                ssh_info = self.ssh_info(port, data)
                self.output += ssh_info
            if "nsmtp" in data:
                smtp_info = self.smtp_info(port, data)
                self.output += smtp_info
            if "dig" in data:
                dns_info = self.dns_info(port, data)
                self.output += dns_info
            if "nsmb" in data:
                smb_info = self.smb_info(port, data)
                self.output += smb_info
            if "nhttp" in data:
                http_info = self.http_info(port, data)
                self.output += http_info
            if "sslscan" in data:
                ssl_info = self.ssl_info(port, data)
                self.output += ssl_info


    def ftp_info(self, port, data):
        title = f"""FTP (Port {port})"""
        product = data.get("nftp", {}).get("product")
        version = data.get("nftp", {}).get("version")
        extra_info = data.get("nftp", {}).get("extrainfo")
        anon_login = data.get("aftp", {}).get("anonymous_login")
        credentials = "\n".join(f"{creds['login']}:{creds['password']}" for creds in data.get("hydra", {}).values())
        directories = data.get("nftp", {}).get("directory_listing")
        bounce = data.get("nftp", {}).get("ftp_bounce_vulnerable")
        proftpd_bd = data.get("nftp", {}).get("proftpd_backdoor")
        vsftpd_bd = data.get("nftp", {}).get("vsftpd_backdoor")
        vuln_cve2010_4221 = data.get("nftp", {}).get("ftp_vuln_cve2010_4221")
        vuln_cve2010_1938 = data.get("nftp", {}).get("ftp_vuln_cve2010_1938")

        return f"""
                {"-" * 30}
                {title}
                Product: {product}
                Version: {version}
                Extra Info: {extra_info}
                Anonymous Login: {anon_login}
                Credentials: {credentials}
                Directory Listing: {directories}
                FTP Bounce: {bounce}
                ProFTPD Backdoor: {proftpd_bd}
                VSFTPD Backdoor: {vsftpd_bd}
                CVE-2010-4221: {vuln_cve2010_4221}
                CVE-2010-1938: {vuln_cve2010_1938}
                """

    def ssh_info(self, port, data):
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
                algorithms += f" - {alg}: {data['fail'] if data['fail'] else "(no fail)"}; {data['warn'] if data['warn'] else "(no warn)"}\n"

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
                \t{algorithms}
                """

    def smtp_info(self, port, data):
        title = f"""SMTP (Port {port})"""
        product = data.get("nsmtp", {}).get("product")
        version = data.get("nsmtp", {}).get("version")
        extra_info = data.get("nsmtp", {}).get("extrainfo")
        smtp_commands = data.get("nsmtp", {}).get("smtp_commands")
        open_relay = data.get("nsmtp", {}).get("open_relay")
        enum_users = data.get("nsmtp", {}).get("enum_users")
        vuln_cve2010_4344 = data.get("nsmtp", {}).get("vuln_cve2010_4344")

        return f"""
                {"-" * 30}
                {title}
                Product: {product}
                Version: {version}
                Extra Info: {extra_info}
                SMTP Commands: {smtp_commands}
                Open Relay: {open_relay}
                Enum Users: {enum_users}
                CVE-2010-4344: {vuln_cve2010_4344}
                """

    def dns_info(self, port, data):
        title = f"""DNS (Port {port})"""

        information_disclosure = False
        open_resolver = False
        amplification = False

        for item in data.get("dig", {}).values():
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

    def smb_info(self, port, data):
        title = f"""SMB (Port {port})"""
        product = data.get("nsmb", {}).get("product")
        version = data.get("nsmb", {}).get("version")
        dialects = data.get("nsmb", {}).get("dialects")
        vuln_ms10_054 = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-ms10-054")
        vuln_regsvc_dos = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-regsvc-dos")
        vuln_ms10_061 = data.get("nsmb", {}).get("vulnerabilities", {}).get("smb-vuln-ms10-061")
        users = ""
        pass_lenght = data.get("enum4linux", {}).get("policy", {}).get("password_lenght")
        pass_complex = data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_COMPLEX")
        pass_cleartext = data.get("enum4linux", {}).get("policy", {}).get("DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT")

        for uuid, user in data.get("enum4linux", {}).get("users", {}).items():
            users += f" - {user}\n"

        return f"""
                {"-" * 30}
                {title}
                Product: {product}
                Version: {version}
                Dialects: {dialects}
                Vulnerable To MS10-054: {vuln_ms10_054}
                Vulnerable To REGSVR32: {vuln_regsvc_dos}
                Vulnerable To MS10-061: {vuln_ms10_061}
                Users: 
                \t{users}
                Min Password Lenght Required: {pass_lenght}
                Password Complexity Required: {pass_complex}
                Password Stored In Cleartext: {pass_cleartext}
                """

    def http_info(self, port, data):
        title = f"""HTTP (Port {port})"""
        website_title = data.get("nhttp", {}).data.get("http-title")
        git_url = data.get("nhttp", {}).get("http-git", {}).get("url")
        git_type = data.get("nhttp", {}).get("http-git", {}).get("type")
        robots = ""
        auth = ""
        methods = data.get("nhttp", {}).get("http-methods")
        waf = data.get("nhttp", {}).get("http_waf_detect")
        open_proxy = data.get("nhttp", {}).get("http_open_proxy")
        nikto_msg = ""
        paths = ""

        for path in data.get("nhttp", {}).get("http_robots"):
            robots += f" - {path}\n"
        for url in data.get("nhttp", {}).get("http_auth_finder"):
            auth += f" - {url}\n"
        for i in data.get("nikto", []):
            nikto_msg += f" - {i.get("msg")}\n"

        ffuf_2 = []
        ffuf_3 = []
        ffuf_4 = []
        for item in data.get("ffuf", []):
            if item.get("status") in ["200", "204"]:
                ffuf_2.append(f"{item.get("url")}: {item.get("status")}")
            elif item.get("status") in ["301", "302", "307"]:
                ffuf_3.append(f"{item.get("url")}: {item.get("status")}")
            elif item.get("status") == "401":
                ffuf_4.append(f"{item.get("url")}: {item.get("status")}")
            else:
                printwarn(f"Unhandled status code: {item.get("status")}, ignoring")

        for path in ffuf_2:
            paths += f" - {path}\n"
        for path in ffuf_3:
            paths += f" - {path}\n"
        for path in ffuf_4:
            paths += f" - {path}\n"

        return f"""
                {title}
                Website Title: {website_title}
                Login URLs: 
                \t{auth}
                Git Project URL: {git_url}
                Git Project Type: {git_type}
                Hidden Directories (Robots.txt): 
                \t{robots}
                Accepted Risky Methods: 
                \t{methods}
                Web Application Firewall: {waf}
                Open Proxy: {open_proxy}
                Warnings Messages: 
                \t{nikto_msg}
                Found Paths: 
                \t{paths}
                """

    def ssl_info(self, port, data):
        return None