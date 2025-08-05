import os

from execute_command import execute_command


class Enum4Linux:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"enum4linux_{self.port}_{self.timestamp}.json")

    def run_enum4linux(self):
        cmd = f"enum4linux-ng {self.ip} -A -C -R -oJ {self.output_file}"
        return execute_command(cmd, "Enum4Linux", self.output_file, self.ip)