from nmap import nmap

class NSSH:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.nm = nmap.PortScanner()

    def run_nssh(self):
        args = f"-sC -sV --script=ssh-* -p {self.port}"
        try:
            print(f"\nStarting SSH nmap scan at {self.timestamp}")
            self.nm.scan(hosts=self.ip, arguments=args)

            return self.nm.get_nmap_last_output()


        except nmap.PortScannerError as e:
            print(f"Nmap error: {e}")
            print("Make sure Nmap is installed and in your PATH, and you have necessary permissions.")
            return None
        except KeyError as e:
            print(f"Key error accessing scan results: {e}")
            print("This might indicate the FTP host is not responding or the scan failed.")
            return None
        except Exception as e:
            print(f"Unexpected error during SSH nmap scan: {e}")
            return None