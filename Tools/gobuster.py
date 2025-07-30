import os
import re

from execute_command import execute_command

class Gobuster:
    def __init__(self, url, port, tools_dir, timestamp, threads):
        self.url = url
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.threads = threads
        self.output_file = os.path.join(tools_dir, f"Gobuster_{self.port}_{self.timestamp}.txt")
        self.wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", "big.txt")

    def run_gobuster(self):
        """Run Gobuster directory enumeration"""
        print("\n" + self.url + "\n")
        cmd = f"gobuster dir -w {self.wordlist_path} -t {self.threads} -r -d -k -u {self.url} -o {self.output_file}"
        return execute_command(cmd, "Gobuster", self.output_file, self.url)

    def extract_data(self):
        """Extract data from Gobuster output"""
        parsed_data = {}

        with open(self.output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Use regex to extract path and status code
                # Pattern matches: path (Status: code) [Size: bytes]
                match = re.match(r'^(.+?)\s+\(Status:\s+(\d+)\)', line)

                if match:
                    path = match.group(1).strip()
                    status_code = int(match.group(2))
                    parsed_data[path] = status_code

        return parsed_data