import os
import socket
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from Tools import nikto, wpscan, whatweb, sslscan, ffuf, ssh_audit, hydra, dig, anonym_ftp, enum4linux
from Tools.Nmap import nmap_FTP, nmap_SSH, nmap_SMTP, nmap_SMB, nmap_HTTP
#from Tools import gobuster
from ssl_domain_extractor import get_domain_from_ip
from printer import printerr, printwarn, printout

class Dispatcher:
    def __init__(self, target_ip, output_dir, max_threads):
        self.target_ip = target_ip
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results = {}
        self.max_threads = max_threads

        # Create tools output directory
        self.tools_dir = os.path.join(output_dir, "tools")
        if not os.path.exists(self.tools_dir):
            os.makedirs(self.tools_dir)

    def analyze(self, services_dict):

        if not services_dict:
            printwarn("No services to analyze")
            return None

        printout(f"--- Starting Service Analysis for {self.target_ip} ---")

        # Use ThreadPoolExecutor for concurrent tool execution
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []

            for port, service_info in services_dict.items():
                if isinstance(service_info, dict):
                    service_info['port'] = port  # Ensure port is in service_info

                    # Submit tasks based on service type
                    if service_info['name'] in ['http', 'https', 'ssl/http']:
                        futures.append(executor.submit(self.analyze_web_service, service_info))
                    elif service_info['name'] == 'ssh':
                        futures.append(executor.submit(self.analyze_ssh_service, service_info))
                    elif service_info['name'] == 'ftp':
                        futures.append(executor.submit(self.analyze_ftp_service, service_info))
                    elif service_info['name'] in ['mysql', 'postgresql', 'mssql', 'ms-sql-s', 'mongodb', 'redis', 'oracle-tns', 'oracle']:
                        futures.append(executor.submit(self.analyze_database_service, service_info))
                    elif service_info['name'] in ['dns', 'domain'] or service_info.get('port') == 53:
                        futures.append(executor.submit(self.analyze_dns_service, service_info))
                    elif service_info['name'] in ['smtp', 'submission']:
                        futures.append(executor.submit(self.analyze_smtp_service, service_info))
                    elif service_info['name'] in ['smb', 'netbios-ssn', 'microsoft-ds']:
                        futures.append(executor.submit(self.analyze_smb_service, service_info))
                    else:
                        futures.append(executor.submit(self.analyze_generic_service, service_info))

            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.update(result)
                except Exception as e:
                    printerr(f"Error in service analysis: {e}")


        return self.results

    def analyze_web_service(self, service_info):
        """Analyze HTTP/HTTPS services with multiple tools"""
        printout(f"Analyzing web service on port {service_info['port']}")
        results = {}

        if service_info['name'] == 'ssl/http' or service_info['name'] == 'https':
            protocol = 'https'
        else:
            protocol = 'http'

        base_url = f"{protocol}://{self.target_ip}:{service_info['port']}"

        if protocol == 'https':
            base_url = f"https://{get_domain_from_ip(base_url)}"
            printout(f"Extracted Domain {base_url} from IP: {self.target_ip}:{service_info['port']}")
            results['sslscan'] = sslscan.SSLScan(base_url, self.tools_dir, self.timestamp).run_sslscan()

        # Nikto scan
        results['nikto'] = nikto.Nikto(base_url, service_info['port'], self.tools_dir, self.timestamp).run_nikto()

        # Gobuster directory enumeration -> Will use FFUF
        #results['gobuster'] = gobuster.Gobuster(base_url, service_info['port'], self.tools_dir, self.timestamp, self.max_threads).run_gobuster()

        #Nmap HTTP script
        results['nmap_http'] = nmap_HTTP.NHTTP(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_nhttp()

        #FUFF direcory enumeration
        results['ffuf'] = ffuf.FFUF(base_url, service_info['port'], self.tools_dir, self.timestamp, self.max_threads).run_ffuf()

        # Whatweb technology identification
        results['whatweb'] = whatweb.Watweb(base_url, service_info['port'], self.tools_dir, self.timestamp, self.max_threads).run_whatweb()

        #WPScan vulnerability scanner
        results['wpscan'] = wpscan.WPScan(base_url, service_info['port'], self.tools_dir, self.timestamp).run_wpscan()

        return {f"web_{service_info['port']}": results}


    def analyze_ssh_service(self, service_info):
        """Analyze SSH service"""
        printout(f"Analyzing SSH service on port {service_info['port']}")
        results = {}

        #base_url = f"ssh://{self.target_ip}:{service_info['port']}"

        # Nmap SSH script
        results['nmap_ssh'] = nmap_SSH.NSSH(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_nssh()

        # SSH audit
        results['ssh_audit'] = ssh_audit.SSH_Audit(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_ssh_audit()

        # Hydra brute force (with common usernames)
        results['hydra_ssh'] = hydra.Hydra(self.target_ip, service_info['port'], "ssh", self.tools_dir, self.timestamp).run_hydra()

        return {f"ssh_{service_info['port']}": results}

    def analyze_ftp_service(self, service_info):
        """Analyze FTP service"""
        printout(f"Analyzing FTP service on port {service_info['port']}")
        results = {}

        #base_url = f"ftp://{self.target_ip}:{service_info['port']}"

        #Nmap FTP script
        results['nmap_ftp'] = nmap_FTP.NFTP(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_nftp()

        # Hydra FTP brute force
        results['hydra_ftp'] = hydra.Hydra(self.target_ip, service_info['port'], "ftp", self.tools_dir, self.timestamp).run_hydra()

        #Check FTP anonymous login
        results['ftp_anon'] = anonym_ftp.AFTP(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_anonym_ftp()

        return {f"ftp_{service_info['port']}": results}

    def analyze_database_service(self, service_info):
        """Analyze database services"""
        printout(f"Analyzing database service {service_info['name']} on port {service_info['port']}")
        results = {}

        # SQLMap for web-accessible databases
        if service_info['name'] == 'mysql':
            results['hydra_mysql'] = hydra.Hydra(self.target_ip, service_info['port'], "mysql", self.tools_dir, self.timestamp).run_hydra()
        elif service_info['name'] == 'postgresql':
            results['hydra_postgresql'] = hydra.Hydra(self.target_ip, service_info['port'], "postgres", self.tools_dir, self.timestamp).run_hydra()
        elif service_info['name'] == 'ms-sql-s':
            results['hydra_mssql'] = hydra.Hydra(self.target_ip, service_info['port'], "mssql", self.tools_dir, self.timestamp).run_hydra()
        elif service_info['name'] == 'mongodb':
            results['hydra_mongodb'] = hydra.Hydra(self.target_ip, service_info['port'], "mongodb", self.tools_dir, self.timestamp).run_hydra()
        elif service_info['name'] == 'redis':
            results['hydra_redis'] = hydra.Hydra(self.target_ip, service_info['port'], "redis", self.tools_dir, self.timestamp).run_hydra()
        elif service_info['name'] == 'oracle-tns' or service_info['name'] == 'oracle':
            results['hydra_oracle'] = hydra.Hydra(self.target_ip, service_info['port'], "oracle-listener", self.tools_dir, self.timestamp).run_hydra()


        return {f"db_{service_info['name']}_{service_info['port']}": results}

    def analyze_dns_service(self, service_info):
        """Analyze DNS service"""
        printout(f"Analyzing DNS service on port {service_info['port']}")
        results = {}

        # DNS enumeration
        results['dig'] = dig.Dig(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_dig()

        return {f"dns_{service_info['port']}": results}

    def analyze_smtp_service(self, service_info):
        """Analyze SMTP service"""
        printout(f"Analyzing SMTP service on port {service_info['port']}")
        results = {}

        # SMTP enumeration
        results['nmap_smtp'] = nmap_SMTP.NSMTP(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_nsmtp()

        return {f"smtp_{service_info['port']}": results}

    def analyze_smb_service(self, service_info):
        """Analyze SMB service"""
        printout(f"Analyzing SMB service on port {service_info['port']}")
        results = {}

        # SMB enumeration
        results['nmap_ftp'] = nmap_SMB.NSMB(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_nsmb()

        results['enum4linux'] = enum4linux.Enum4Linux(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_enum4linux()

        return {f"smb_{service_info['port']}": results}

    def analyze_generic_service(self, service_info):
        """Analyze generic/unknown services"""
        printout(f"Analyzing generic service {service_info['name']} on port {service_info['port']}")

        #Check if service is in fact HTTP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4)
        sock.connect((self.target_ip, int(service_info['port'])))
        # Send minimal HTTP request
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        # Read first bytes of response
        response = sock.recv(12)
        sock.close()

        # Check if response starts with HTTP
        if response.startswith(b"HTTP/"):
            printout(f"Service {service_info['name']} on port {service_info['port']} is HTTP")
            return self.analyze_web_service(service_info)
        else:
            results = {}

            return {f"generic_{service_info['name']}_{service_info['port']}": results}