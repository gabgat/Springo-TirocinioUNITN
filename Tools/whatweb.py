import os

from execute_command import execute_command

class Watweb:
    def __init__(self, url, tools_dir, timestamp, threads):
        self.url = url
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.threads = threads
        self.output_file = os.path.join(tools_dir, f"whatweb_{self.timestamp}.json")

    def run_whatweb(self):
        """Run WhatWeb technology identification"""
        cmd = f"whatweb {self.url} --log-brief={self.output_file} --max-threads {self.threads}"
        return execute_command(cmd, "WhatWeb", self.output_file)

