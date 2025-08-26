import json
import os

from nmap import nmap
from printer import printerr, printout

class NHTTP:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.nm = nmap.PortScanner()
        self.args = f'-Pn --script=http-* -p {self.port}'
        self.output_file = os.path.join(self.tools_dir, f"nhttp_{self.port}_{self.timestamp}.json")

    def save_json_result(self, raw_output):
        try:
            json_data = {
                "scan_info": {
                    "target_ip": self.ip,
                    "target_port": self.port,
                    "scan_date": self.timestamp,
                    "nmap_version": str(self.nm.nmap_version()),
                    "scan_command": self.args,
                    "scan_type": "HTTP"
                },
                "scan_result": {
                    "raw_output": raw_output
                }
            }

            with open(self.output_file, 'w', encoding='utf-8') as json_file:
                json.dump(json_data, json_file, indent=2, ensure_ascii=False)

            printout(f"NHTTP JSON results saved to: {self.output_file}")

            return json_data

        except Exception as e:
            printerr(f"Error saving JSON file: {e}")
            return None

    def run_nhttp(self):
        try:
            printout(f"Starting HTTP nmap scan at {self.port}")
            raw_output = self.nm.scan(hosts=self.ip, arguments=self.args)

            # Save JSON result
            self.save_json_result(raw_output)

            return raw_output


        except nmap.PortScannerError as e:
            printerr(f"Nmap error: {e}")
            printerr("Make sure Nmap is installed and in your PATH, and you have necessary permissions.")
            return None
        except KeyError as e:
            printerr(f"Key error accessing scan results: {e}")
            printerr("This might indicate the HTTP host is not responding or the scan failed.")
            return None
        except Exception as e:
            printerr(f"Unexpected error during HTTP nmap scan: {e}")
            return None