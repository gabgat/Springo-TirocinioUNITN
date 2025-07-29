#!/usr/bin/sudo python3

import argparse
import shutil
import sys
import os
from datetime import datetime

from Tools.Nmap.nmap_Scanner import IPScanner
from ServiceDispatcher import Dispatcher


def setup_output_directory(target_ip):
    """Create organized output directory structure"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_dir = f"scan_{target_ip}_{timestamp}"

    dirs_to_create = [
        base_dir,
        os.path.join(base_dir, "tools"),
        os.path.join(base_dir, "reports")
    ]

    for directory in dirs_to_create:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"  - Created directory: {directory}")

    return base_dir


def check_required_tools():
    """Check if required security tools are installed"""
    tools = [
        'nmap',
        'nikto',
        'gobuster',
        'whatweb',
        'sslscan',
        'ffuf',
        'hydra',
        'ssh-audit'
        #'enum4linux'
        #'smbclient'
        #'dnsrecon'
        #'dnsenum'
    ]

    print("\nChecking required tools...")
    missing_tools = []

    for tool in tools:
        try:
            # Using shutil.which() - simplest and most reliable method
            if shutil.which(tool) is not None:
                print(f"  -> {tool} - Found")
            else:
                missing_tools.append(tool)
                print(f"  -> {tool} - Not found")
        except Exception:
            print(f"  {tool} - Not found")
            missing_tools.append(tool)

    if missing_tools:
        print(f"\nMissing tools: {', '.join(missing_tools)}")
        print("Some scans may not work properly or give errors. Install missing tools for full functionality.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    else:
        print("\nAll tools are available!")

def print_scan_progress(stage, message):
    """Print formatted progress messages"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"\n[{timestamp}] -> {stage}: {message}")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Automatic vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    Intensity Levels:
      0 - Quick scan (basic service detection)
      1 - Normal scan (service detection + basic scripts)
      2 - Advanced scan (full port range + version detection)
      3 - Stealth scan (slow, comprehensive, evasive)

    Examples:
      %(prog)s 192.168.1.100 1                    # Normal scan
      %(prog)s 10.0.0.1 2 --skip-tools            # Advanced scan, skip additional tools
      %(prog)s 172.16.0.1 3 --tools-only nikto,dirb  # Stealth scan, only run specified tools
            """
    )
    parser.add_argument("ip", help="The IP address of the target machine")
    parser.add_argument("--intensity", "-i", type=int, choices=[0, 1, 2, 3], default=1,
                        help="Scan intensity level (0-3) - (default: 1)")
    parser.add_argument("--max-threads", "-t", type=int, default=10,
                        help="Number of max threads to use - (default: 10)")
    parser.add_argument("--output-dir", "-o", default=None,
                        help="Custom output directory - (default: auto-generated)")
    args = parser.parse_args()

    #Check tools
    check_required_tools()

    # Setup output directory
    if args.output_dir:
        print(f"\nSetting up custom output directory: {args.output_dir}")
        output_dir = args.output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    else:
        print("\nSetting up auto-generated output directory")
        output_dir = setup_output_directory(args.ip)

    print(f"\nUsing output directory: {output_dir}")

    try:
        print("\n\n")
        print("-" * 50)
        print(" STARTING ")
        print("-" * 50)
        print("\n")

        # Stage 1: Nmap Scanning
        print_scan_progress("STAGE 1", "Nmap Network Scanning...")

        scan_results = IPScanner(args.ip, args.intensity, os.path.join(output_dir, "tools")).run()

        if not scan_results:
            print("Nmap scan failed. Exiting...")
            sys.exit(101)

        print(f"Nmap scan completed. Found {len(scan_results.get('open_ports', []))} open ports!")

        #Service Analysis
        print_scan_progress("STAGE 2", "Service-specific Analysis...")

        dispatcher = Dispatcher(args.ip, output_dir)

        vulnerability_results = dispatcher.analyze(scan_results.get('services', {}), args.max_threads)

        print("Service analysis completed!")

        print("\n\n")
        print("-" * 50)
        print(" SCAN SUMMARY ")
        print("-" * 50)
        print("\n")
        print(f"- Target: {args.ip}")
        print(f"- Intensity Level: {args.intensity}")
        print(f"- Open Ports: {len(scan_results.get('open_ports', []))}")
        print(f"- Services Detected: {len(scan_results.get('services', {}))}")

        print(f"- Output Directory: {output_dir}")

        # Display open ports and services
        if scan_results.get('open_ports'):
            print("\nOPEN PORTS:")
            for port in scan_results['open_ports']:
                protocol = scan_results.get('services', {}).get(port, {}).get('protocol', 'unknown')
                service_info = scan_results.get('services', {}).get(port, {})
                service_name = service_info.get('name', 'unknown')
                product = service_info.get('product', '')
                version = service_info.get('version', '')

                service_str = service_name
                if product and product != 'N/A':
                    service_str += f" ({product}"
                    if version and version != 'N/A':
                        service_str += f" {version}"
                    service_str += ")"

                print(f"  {port}/{protocol} - {service_str}")

    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':

    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(99)

    main()