import os

from execute_command import execute_command

class Nikto:
    def __init__(self, url, tools_dir, timestamp):
        self.url = url
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"nikto_{self.timestamp}.json")

    def run_nikto(self):
        """Run Nikto web vulnerability scanner"""
        cmd = f"nikto -Tuning x -C all -output {self.output_file} -ask no -evasion B -Cgidirs all -url {self.url}"
        return execute_command(cmd, "Nikto", self.output_file)