import os

from execute_command import execute_command


class SmtpUserEnum:
    def __init__(self, ip, port, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.url = f"smtp://{self.ip}:{self.port}"
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"SmtpUserEnum_{self.port}_{self.timestamp}.txt")

        self.wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", "multiplesources-users-fabian-fingerle.de.txt")

    def run_hydra(self):
        # Code to run Smtp User Enum
        cmd = f"smtp-user-enum -M VRFY -U {self.wordlist} -t {self.ip} -p {self.port} >> {self.output_file}; smtp-user-enum -M EXPN -U {self.wordlist} -t {self.ip} -p {self.port} >> {self.output_file}"
        return execute_command(cmd, "SmtpUserEnum", self.output_file, self.url)