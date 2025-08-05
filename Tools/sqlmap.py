import os

from execute_command import execute_command

class SQLMap:
    def __init__(self, url, port, tools_dir, timestamp, threads):
        self.url = url
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.threads = threads
        self.output_file = os.path.join(tools_dir, f"sqlmap_{self.port}_{self.timestamp}.json")

    def run_sqlmap(self):
        cmd = f"sqlmap -u {self.url} --level=5 --risk=3 -a --batch -f --output-dir={self.output_file}"
        return execute_command(cmd, "SQLMap", self.output_file, self.url)