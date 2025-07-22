import ipaddress
import nmap

from datetime import datetime
from nmap_ScanResult import ScanResult

class IPScanner:
    def __init__(self, ip, intensity):
        self.ip = ip
        self.intensity = intensity
        self.nm = nmap.PortScanner()
        self.scan_configs = {
            0: {  # Useless scan
                'args': '-T4 --source-port 53 -sV -O --osscan-guess --open'
            },
            1: {  # Normal scan
                'args': '-T3 --source-port 53 -D RND:5,ME --data-length 25 --reason -sV -O --osscan-guess --open'
            },
            2: {  # Advanced scan
                'args': '-p1-65535 -T2 --max-retries 3 -f --source-port 53 -D RND:5,ME --data-length 25 --reason -sV --version-intensity 5 -O --osscan-guess --open'
            },
            3: {  # Stealth scan
                'args': '-p1-65535 -T2 --scan-delay 1s -f --source-port 53 -D RND:10,ME --data-length 25 --reason -sV --version-all -O --osscan-guess --open'
            }
        }

    def sanitize_ip(self):
        try:
            # Validate IP address
            ip = ipaddress.ip_address(self.ip)
            print(f"\nIP {ip} is valid")
            return True
        except ValueError:
            print(f"\nError: {self.ip} is not a valid IP address")
            return False
        except Exception as e:
            print(f"\nUnexpected error validating IP: {str(e)}")
            return False


    def start_scan(self, ip, intensity):
        print(f'\nUsing Nmap versrion: {self.nm.nmap_version()}')
        print(f'\nScanning {ip} with intensity {intensity}')
        #ports = self.scan_configs[intensity]['ports']
        args = self.scan_configs[intensity]['args']
        try:
            print(f"\nStarting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            #self.nm.scan(ip, ports, args)
            self.nm.scan(hosts=ip, arguments=args)

            if not self.nm.all_hosts():
                print(f"\nNo host found for {ip}.")
                return None
            if self.nm[ip].state() != 'up':
                print(f"\nIs the host at {ip} down?")
                return None

            #print(self.nm.get_nmap_last_output())

            # Estrai i dati dell'host
            host_data = self.nm[ip]

            # Estrai hostnames
            hostnames = self.extract_hostnames(host_data)

            # Estrai porte aperte e servizi (TCP e UDP)
            open_ports, services = self.extract_ports_and_services(host_data)

            # Estrai informazioni OS
            os_info = self.extract_os_info(host_data)

            print(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            return ScanResult(ip, hostnames, open_ports, services, os_info)


        except nmap.PortScannerError as e:
            print(f"Nmap error: {e}")
            print("Make sure Nmap is installed and in your PATH, and you have necessary permissions.")
            return None
        except KeyError as e:
            print(f"Key error accessing scan results: {e}")
            print("This might indicate the host is not responding or the scan failed.")
            return None
        except Exception as e:
            print(f"Unexpected error during scan: {e}")
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
                    open_ports.append(port)
                    services[port] = {
                        'protocol': 'tcp',
                        'name': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'state': port_info.get('state', ''),
                        'reason': port_info.get('reason', '')
                    }

        # Estrai porte UDP se presenti
        if 'udp' in host_data:
            for port in host_data['udp']:
                port_info = host_data['udp'][port]
                if port_info['state'] in ['open', 'open|filtered']:
                    open_ports.append(f"{port}/udp")
                    services[f"{port}/udp"] = {
                        'protocol': 'udp',
                        'name': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'state': port_info.get('state', ''),
                        'reason': port_info.get('reason', '')
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
        print("\nChecking IP Address...")
        if not self.sanitize_ip():
            exit(100)

        print("\nStarting Scan Phase...")
        scan_result = self.start_scan(self.ip, self.intensity)
        print("\nScan finished")
        if scan_result:
            print("\n--- Scan Results ---")
            print(scan_result)
            print("---------------------------\n")

            return scan_result.to_dict()

        else:
            print("\nScan failed or no results obtained.")
            return None