import os

from execute_command import execute_command


class SSLScan:
    def __init__(self, url, tools_dir, timestamp):
        self.url = url
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.output_file = os.path.join(self.tools_dir, f"sslscan_{self.timestamp}.xml")

    def run_sslscan(self):
        """Run SSLScan for SSL/TLS analysis"""
        cmd = f"sslscan {self.url} --xml={self.output_file}"
        return execute_command(cmd, "SSLScan", self.output_file, self.url)