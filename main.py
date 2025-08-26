#!/usr/bin/sudo python3

import argparse
import shutil
import sys
import os
from datetime import datetime

from Tools.Nmap.nmap_Scanner import IPScanner
from cve_analyzer import CVEChecker
from service_dispatcher import Dispatcher
from results_parser import ResultParser
from results_analyzer import ResultAnalyzer
from results_txt_printer import PrintTXT
from printer import printerr, printwarn, printout, printsec


def setup_output_directory(target_ip, timestamp):
    """Create organized output directory structure"""
    base_dir = f"scan_{target_ip}_{timestamp}"

    dirs_to_create = [
        base_dir,
        os.path.join(base_dir, "tools"),
        os.path.join(base_dir, "reports")
    ]

    for directory in dirs_to_create:
        if not os.path.exists(directory):
            os.makedirs(directory)
            printout(f"Created directory: {directory}")

    return base_dir


def check_required_tools():
    """Check if required security tools are installed"""
    tools = [
        'nmap',
        'nikto',
        'whatweb',
        'sslscan',
        'ffuf',
        'hydra',
        'ssh-audit',
        'wpscan',
        'dig',
        'enum4linux-ng'
    ]

    printsec("Stage 0 - Checking required tools...")
    missing_tools = []

    for tool in tools:
        try:
            if shutil.which(tool) is not None:
                printout(f"{tool} Found")
            else:
                missing_tools.append(tool)
                printwarn(f"{tool} Not found")
        except Exception:
            printwarn(f"{tool} Not found")
            missing_tools.append(tool)

    if missing_tools:
        printwarn(f"Missing tools: {', '.join(missing_tools)}")
        printwarn("Some scans may not work properly or give errors. Install missing tools for full functionality.")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    else:
        printout("All tools are available!")


def main():
    start_time = datetime.now().strftime('%Y%m%d_%H%M%S')
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
        printout(f"Setting up custom output directory: {args.output_dir}")
        output_dir = args.output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    else:
        printout("Setting up auto-generated output directory")
        output_dir = setup_output_directory(args.ip, start_time)

    printout(f"Using output directory: {output_dir}")

    try:
        printout("STARTING... ")

        # Stage 1: Nmap Scanning
        printsec("STAGE 1 - Nmap Network Scanning...")

        scan_results = IPScanner(args.ip, args.intensity, os.path.join(output_dir, "tools")).run()

        if not scan_results:
            printerr("Nmap scan failed. Exiting...")
            sys.exit(101)

        printout(f"Nmap scan completed. Found {len(scan_results.get('open_ports', []))} open ports!")

        #Service Analysis
        printsec("STAGE 2 - Service-specific Analysis...")

        Dispatcher(args.ip, output_dir, args.max_threads).analyze(scan_results.get('services', {}))

        printout("Service analysis completed!")

        #Results Analysis
        printsec("STAGE 3 - Analyzing Results...")

        printout("Loading results from files")
        loaded_results = ResultParser(output_dir).start()
        printout("Results loaded!")
        printout("Selecting useful results")
        results = ResultAnalyzer(loaded_results).start()
        printout("Starting CVEs search")
        cves = None#CVEChecker(output_dir).analyze_scan_results(results)
        printout("Results analysis completed!")

        #Creating Summary
        printsec("STAGE 4 - Creating Output Files...")
        printout(f"Target: {args.ip}")
        printout(f"Intensity Level: {args.intensity}")
        printout(f"Open Ports: {len(scan_results.get('open_ports', []))}")
        printout(f"Services Detected: {len(scan_results.get('services', {}))}")
        printout(f"Output Directory: {output_dir}")
        end_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        printout(f"Script finished at {end_time}")
        printout(f"Generating text report at {output_dir}/reports/report.txt...")
        PrintTXT(output_dir, results, cves, start_time, end_time).print_results()

        #End Message
        printsec(f"!!SCAN FINISHED!!")
        printout(f"Reports Saved At {output_dir}/reports/")

    except KeyboardInterrupt:
        printerr("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        printerr(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':

    if os.geteuid() != 0:
        printerr("This script must be run as root.")
        sys.exit(99)

    main()