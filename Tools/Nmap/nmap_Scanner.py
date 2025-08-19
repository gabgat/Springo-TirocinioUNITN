import ipaddress
import nmap
import os
import json

from datetime import datetime
from Tools.Nmap.nmap_ScanResult import ScanResult
from printer import printerr, printwarn, printout


class IPScanner:
    def __init__(self, ip, intensity, output_dir):
        self.ip = ip
        self.intensity = intensity
        self.nm = nmap.PortScanner()
        self.output_dir = output_dir
        self.base_filename = f"nmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        self.scan_configs = {
            0: {  # Useless scan
                'args': '-T4 --source-port 53 -sV --version-intensity 5 -O --osscan-guess --open'
            },
            1: {  # Normal scan
                'args': '-T3 --source-port 53 -D RND:5,ME -f --reason -sS -sC -sV --version-intensity 5 -O --osscan-guess --open'
            },
            2: {  # Advanced scan
                'args': '-p1-65535 -T3 --max-retries 2 -f --source-port 53 -D RND:5,ME --data-length 25 --reason -sS -sC -sV --version-all -O --osscan-guess --open'
            },
            3: {  # Stealth scan
                'args': '-p1-65535 -T2 --scan-delay 1s -f --source-port 53 -D RND:10,ME --data-length 25 --reason -sS -sC -sV --version-all -O --osscan-guess --open'
            }
        }

    def sanitize_ip(self):
        try:
            # Validate IP address
            ip = ipaddress.ip_address(self.ip)
            printout(f"{ip} is valid")
            return True
        except ValueError:
            printerr(f"{self.ip} is not a valid IP address")
            return False
        except Exception as e:
            printerr(f"Unexpected error validating IP: {str(e)}")
            return False

    def save_json_result(self, scan_result):
        """Save scan result to JSON file"""
        try:
            json_filename = f"{self.base_filename}.json"
            json_filepath = os.path.join(self.output_dir, json_filename)

            # Create a comprehensive JSON structure
            json_data = {
                "scan_info": {
                    "target_ip": self.ip,
                    "scan_date": datetime.now().isoformat(),
                    "intensity": self.intensity,
                    "nmap_version": str(self.nm.nmap_version()),
                    "scan_command": self.scan_configs[self.intensity]['args']
                },
                "scan_result": scan_result.to_dict()
            }

            with open(json_filepath, 'w', encoding='utf-8') as json_file:
                json.dump(json_data, json_file, indent=2, ensure_ascii=False)

            printout(f"NMAP JSON results saved to: {json_filepath}")
            return json_filepath

        except Exception as e:
            printerr(f"Error saving NMAP JSON file: {e}")
            return None

    def start_scan(self, ip, intensity):
        printout(f'Using Nmap version: {self.nm.nmap_version()}')
        printout(f'Scanning {ip} with intensity {intensity}')
        args = self.scan_configs[intensity]['args']

        try:
            scan_start_time = datetime.now()
            printout(f"Starting scan at {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")

            self.nm.scan(hosts=ip, arguments=args)

            if not self.nm.all_hosts():
                printwarn(f"No host found for {ip}.")
                return None
            if self.nm[ip].state() != 'up':
                printwarn(f"Is the host at {ip} down?")
                return None

            # Estrai i dati dell'host
            host_data = self.nm[ip]

            # Estrai hostnames
            hostnames = self.extract_hostnames(host_data)

            # Estrai porte aperte e servizi (TCP e UDP)
            open_ports, services = self.extract_ports_and_services(host_data)

            # Estrai informazioni OS
            os_info = self.extract_os_info(host_data)

            scan_end_time = datetime.now()
            scan_duration = scan_end_time - scan_start_time

            printout(f"Scan completed at {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            printout(f"Scan duration: {scan_duration}")

            # Create scan result object
            scan_result = ScanResult(ip, hostnames, open_ports, services, os_info)

            # Save results to files
            self.save_json_result(scan_result)

            return scan_result

        except nmap.PortScannerError as e:
            printerr(f"Nmap error: {e}")
            printerr("Make sure Nmap is installed and in your PATH, and you have necessary permissions.")
            return None
        except KeyError as e:
            printerr(f"Key error accessing scan results: {e}")
            printerr("This might indicate the host is not responding or the scan failed.")
            return None
        except Exception as e:
            printerr(f"Unexpected error during scan: {e}")
            return None

    @staticmethod
    def extract_hostnames(host_data):
        """Extract hostnames from host data"""
        hostnames = []
        for hostname_entry in host_data.get('hostnames', []):
            if 'name' in hostname_entry and hostname_entry['name']:
                hostnames.append(hostname_entry['name'])
        return hostnames

    @staticmethod
    def extract_ports_and_services(host_data):
        """Extract open ports and services from TCP and UDP scans"""
        open_ports = []
        services = {}

        # Estrai porte TCP
        if 'tcp' in host_data:
            for port in host_data['tcp']:
                port_info = host_data['tcp'][port]
                if port_info['state'] == 'open':
                    service_name = port_info.get('name', 'unknown')

                    if 'ssl-cert' in port_info.get('script', {}) and service_name == 'http':
                        service_name = 'https'

                    open_ports.append(f"{port}/tcp")

                    services[port] = {
                        'protocol': 'tcp',
                        'name': service_name,
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'state': port_info.get('state', ''),
                        'reason': port_info.get('reason', ''),
                        'scripts': port_info.get('script', {})  # Include script results
                    }

        # Estrai porte UDP se presenti
        if 'udp' in host_data:
            for port in host_data['udp']:
                port_info = host_data['udp'][port]
                if port_info['state'] in ['open', 'open|filtered']:
                    service_name = port_info.get('name', 'unknown')

                    if 'ssl-cert' in port_info.get('script', {}) and service_name == 'http':
                        service_name = 'https'

                    open_ports.append(f"{port}/udp")

                    services[f"{port}/udp"] = {
                        'protocol': 'udp',
                        'name': service_name,
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'state': port_info.get('state', ''),
                        'reason': port_info.get('reason', ''),
                        'scripts': port_info.get('script', {})  # Include script results
                    }

        return open_ports, services

    @staticmethod
    def extract_os_info(host_data):
        """Extract OS information with better parsing"""
        os_info = {}

        # Informazioni di base dell'host
        if 'addresses' in host_data:
            os_info['addresses'] = host_data['addresses']

        # OS Detection
        if 'osmatch' in host_data and host_data['osmatch']:
            best_match = host_data['osmatch'][0]  # Il primo è solitamente il migliore
            os_info['name'] = best_match.get('name', 'Unknown')
            os_info['accuracy'] = f"{best_match.get('accuracy', 0)}%"

            # Estrai osclass information
            if 'osclass' in best_match and best_match['osclass']:
                osclass = best_match['osclass'][0]
                os_info['osfamily'] = osclass.get('osfamily', 'Unknown')
                os_info['vendor'] = osclass.get('vendor', 'Unknown')
                os_info['type'] = osclass.get('type', 'Unknown')
                os_info['osgen'] = osclass.get('osgen', 'Unknown')
                if 'cpe' in osclass:
                    os_info['cpe'] = osclass['cpe']

        # Uptime se disponibile
        if 'uptime' in host_data:
            uptime_info = host_data['uptime']
            if 'lastboot' in uptime_info:
                os_info['uptime'] = f"Last boot: {uptime_info['lastboot']}"

        return os_info

    def run(self):
        printout("Checking IP Address...")
        if not self.sanitize_ip():
            exit(100)

        printout("Starting Scan Phase...")
        scan_result = self.start_scan(self.ip, self.intensity)
        printout("Scan finished")

        if scan_result:
            printout("------ Scan Results ------")
            for line in str(scan_result).splitlines():
                printout(line)
            printout("---------------------------\n")

            return scan_result.to_dict()
        else:
            printerr("Scan failed or no results obtained.")
            return None