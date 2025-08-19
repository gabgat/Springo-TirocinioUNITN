import json
import os

from nmap import nmap
from printer import printerr, printout


class NFTP:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.nm = nmap.PortScanner()
        self.args = f"-sC -sV --script=ftp-* -p {self.port}"
        self.output_file = os.path.join(self.tools_dir, f"nftp_{self.port}_{self.timestamp}.json")

    def save_json_result(self, raw_output):
        try:
            json_data = {
                "scan_info": {
                    "target_ip": self.ip,
                    "target_port": self.port,
                    "scan_date": self.timestamp,
                    "nmap_version": str(self.nm.nmap_version()),
                    "scan_command": self.args,
                    "scan_type": "FTP"
                },
                "scan_result": {
                    "raw_output": raw_output
                }
            }

            with open(self.output_file, 'w', encoding='utf-8') as json_file:
                json.dump(json_data, json_file, indent=2, ensure_ascii=False)

            printout(f"NFTP JSON results saved to: {self.output_file}")

            return json_data

        except Exception as e:
            printerr(f"Error saving JSON file: {e}")
            return None

    def run_nftp(self):
        try:
            printout(f"Starting FTP nmap scan at {self.port}")

            raw_output = self.nm.scan(hosts=self.ip, arguments=self.args)

            self.save_json_result(raw_output)

            return raw_output

        except nmap.PortScannerError as e:
            printerr(f"Nmap error: {e}")
            printerr("Make sure Nmap is installed and in your PATH, and you have necessary permissions.")
            return None
        except KeyError as e:
            printerr(f"Key error accessing scan results: {e}")
            printerr("This might indicate the FTP host is not responding or the scan failed.")
            return None
        except Exception as e:
            printerr(f"Unexpected error during FTP nmap scan: {e}")
            return None