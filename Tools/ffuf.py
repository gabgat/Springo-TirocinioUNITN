import os

from execute_command import execute_command

class FFUF:
    def __init__(self, url, port, tools_dir, timestamp, threads):
        self.url = url
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.threads = threads
        self.output_file = os.path.join(tools_dir, f"FFUF_{self.port}_{self.timestamp}.txt")
        self.wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", "big.txt")

    def run_ffuf(self):
        """Run FFUF directory enumeration"""
        cmd = f"ffuf -w {self.wordlist_path} -recursion -u {self.url}/FUZZ -mc 200,204,301,302,307,401,403,415 -ac -t 80 -o {self.output_file}"
        return execute_command(cmd, "FFUF", self.output_file)