from nmap import nmap
from printer import printerr, printout

class NFTP:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.nm = nmap.PortScanner()

    def run_nftp(self):
        args = f"-sC -sV --script=ftp-* -p {self.port}"
        try:
            printout(f"Starting FTP nmap scan at {self.port}")
            self.nm.scan(hosts=self.ip, arguments=args)

            return self.nm.get_nmap_last_output()


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