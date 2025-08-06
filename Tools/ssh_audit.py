import os

from execute_command import execute_command


class SSH_Audit:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.url = f"ssh://{self.ip}:{self.port}"
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"SSH_Audit_{self.port}_{self.timestamp}.txt")

    def run_ssh_audit(self):
        # Code to run SSH audit
        cmd = f"ssh-audit -4 -jj {self.ip} -p {self.port} > {self.output_file}"
        return execute_command(cmd, "SSH Audit", self.output_file, self.url)