import os
import json
from ftplib import FTP, error_perm


class AFTP:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"aftp_{self.port}_{self.timestamp}.txt")
        self.timeout = 5

    def run_anonym_ftp(self):
        result = {
            "ip": self.ip,
            "port": self.port,
            "anonymous_login": False
        }

        try:
            ftp = FTP()
            ftp.connect(self.ip, self.port, timeout=self.timeout)
            ftp.login('anonymous', 'anonymous@gmail.com')
            result["anonymous_login"] = True
            print(f"[+] Anonymous login successful on {self.ip}:{self.port}")
            ftp.quit()

        except error_perm as e:
            print(f"[-] Anonymous login denied on {self.ip}:{self.port} ({e})")
            return False
        except Exception as e:
            print(f"[!] Error connecting to {self.ip}:{self.port} ({e})")
            return False

        with open(self.output_file, "a") as f:
            f.write(json.dumps(result) + "\n")

        return result