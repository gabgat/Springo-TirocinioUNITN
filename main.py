#!/usr/bin/sudo python

import argparse
import ipaddress

from nmap_ScanResult import ScanResult
from nmap_Scanner import Scanner

class IPScan:
    def __init__(self, ip, intensity):
        self.ip = ip
        self.intensity = intensity
        self.scanner = Scanner()

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

    def run(self):
        print("\nChecking IP Address...")
        if not self.sanitize_ip():
            exit(100)

        print("\nStarting Scan Phase...")
        scan_result: ScanResult = self.scanner.start_scan(self.ip, self.intensity)
        print("\nScan finished")
        if scan_result:
            print("\n--- Scan Results ---")
            print(scan_result)
            print("---------------------------\n")



if __name__ == '__main__':
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="The IP of the machine you want to check")
    parser.add_argument("intensity", type=int, choices=[0, 1, 2], help="The intensity of the scan")
    args = parser.parse_args()
    """

    scanner = IPScan("5.180.168.88", 1)
    #scanner = IPScan(args.ip, args.intensity)
    scanner.run()