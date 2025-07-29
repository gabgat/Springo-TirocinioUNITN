import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from Tools import nikto
#from Tools import gobuster
from Tools import whatweb
from Tools import sslscan
from Tools import ffuf
from Tools import ssh_audit
from Tools import hydra
from ssl_domain_extractor import get_domain_from_ip

class Dispatcher:
    def __init__(self, target_ip, output_dir):
        self.target_ip = target_ip
        self.output_dir = output_dir
        self.max_threads = 4
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results = {}

        # Create tools output directory
        self.tools_dir = os.path.join(output_dir, "tools")
        if not os.path.exists(self.tools_dir):
            os.makedirs(self.tools_dir)

    def analyze(self, services_dict, max_threads):
        self.max_threads = max_threads

        if not services_dict:
            print("No services to analyze")
            return None

        print(f"\n--- Starting Service Analysis for {self.target_ip} ---")

        # Use ThreadPoolExecutor for concurrent tool execution
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
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
                    # elif service_info['name'] in ['mysql', 'postgresql', 'mssql']:
                    #     futures.append(executor.submit(self.analyze_database_service, service_info))
                    # elif service_info['name'] == 'dns' or service_info.get('port') == 53:
                    #     futures.append(executor.submit(self.analyze_dns_service, service_info))
                    # elif service_info['name'] == 'smtp':
                    #     futures.append(executor.submit(self.analyze_smtp_service, service_info))
                    # elif service_info['name'] in ['smb', 'netbios-ssn', 'microsoft-ds']:
                    #     futures.append(executor.submit(self.analyze_smb_service, service_info))
                    else:
                        futures.append(executor.submit(self.analyze_generic_service, service_info))

            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.results.update(result)
                except Exception as e:
                    print(f"Error in service analysis: {e}")


        return self.results

    def analyze_web_service(self, service_info):
        """Analyze HTTP/HTTPS services with multiple tools"""
        print(f"Analyzing web service on port {service_info['port']}")
        results = {}

        if service_info['name'] == 'ssl/http' or service_info['name'] == 'https':
            protocol = 'https'
        else:
            protocol = 'http'

        base_url = f"{protocol}://{self.target_ip}:{service_info['port']}"

        if protocol == 'https':
            base_url = f"https://{get_domain_from_ip(base_url)}"
            print(f"Extracted domain from IP: {base_url}")
            results['sslscan'] = sslscan.SSLScan(base_url, self.tools_dir, self.timestamp).run_sslscan()

        # Nikto scan
        results['nikto'] = nikto.Nikto(base_url, self.tools_dir, self.timestamp).run_nikto()

        # Gobuster directory enumeration -> Will use FFUF
        #results['gobuster'] = gobuster.Gobuster(base_url, service_info['port'], self.tools_dir, self.timestamp, self.max_threads).run_gobuster()

        #FUFF direcory enumeration
        results['ffuf'] = ffuf.FFUF(base_url, service_info['port'], self.tools_dir, self.timestamp, self.max_threads).run_ffuf()

        # Whatweb technology identification
        results['whatweb'] = whatweb.Watweb(base_url, self.tools_dir, self.timestamp, self.max_threads).run_whatweb()

        return {f"web_{service_info['port']}": results}


    def analyze_ssh_service(self, service_info):
        """Analyze SSH service"""
        print(f"Analyzing SSH service on port {service_info['port']}")
        results = {}

        # SSH audit
        results['ssh_audit'] = ssh_audit.SSH_Audit(self.target_ip, service_info['port'], self.tools_dir, self.timestamp).run_ssh_audit()

        # Hydra brute force (with common usernames)
        results['hydra_ssh'] = hydra.Hydra(self.target_ip, service_info['port'], "ssh", self.tools_dir, self.timestamp).run_hydra()

        return {f"ssh_{service_info['port']}": results}

    def analyze_ftp_service(self, service_info):
        """Analyze FTP service"""
        print(f"Analyzing FTP service on port {service_info['port']}")
        results = {}

        # Hydra FTP brute force
        results['hydra_ftp'] = hydra.Hydra(self.target_ip, service_info['port'], "ftp", self.tools_dir, self.timestamp).run_hydra()

        return {f"ftp_{service_info['port']}": results}

    # def analyze_database_service(self, service_info):
    #     """Analyze database services"""
    #     print(f"Analyzing database service {service_info['name']} on port {service_info['port']}")
    #     results = {}
    #
    #     # SQLMap for web-accessible databases
    #     if service_info['name'] == 'mysql':
    #         results['mysql_enum'] = self.run_mysql_enum(service_info['port'])
    #         results['hydra_mysql'] = self.run_hydra_mysql(service_info['port'])
    #     elif service_info['name'] == 'postgresql':
    #         results['postgresql_enum'] = self.run_postgresql_enum(service_info['port'])
    #
    #     return {f"db_{service_info['name']}_{service_info['port']}": results}

    def analyze_generic_service(self, service_info):
        """Analyze generic/unknown services"""
        print(f"❓ Analyzing generic service {service_info['name']} on port {service_info['port']}")
        results = {}
        #TODO

        return {f"generic_{service_info['name']}_{service_info['port']}": results}