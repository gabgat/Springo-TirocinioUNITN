#!/usr/bin/sudo python3

import argparse

from Nmap.nmap_Scanner import IPScanner
from ServiceDispatcher import Dispatcher


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="The IP of the machine you want to check")
    parser.add_argument("intensity", type=int, choices=[0, 1, 2, 3], help="Increase the intensity (and duration) of the scan")
    args = parser.parse_args()

    #ip_scanner = IPScanner("5.180.168.88", 1).run()
    ip_scanner = IPScanner(args.ip, args.intensity).run()

    Dispatcher().analyze(ip_scanner['services'])

    for key, value in ip_scanner.items():
        if isinstance(value, list):  # list of values (e.g. hostnames, open_ports)
            print(f"{key}:")
            for item in value:
                print(f"  - {item}")
        elif isinstance(value, dict):  # nested dict (e.g. services, os_info)
            print(f"{key}:")
            for sub_key, sub_val in value.items():
                print(f"  {sub_key}: {sub_val}")
        else:  # simple value such as the IP address string
            print(f"{key}: {value}")