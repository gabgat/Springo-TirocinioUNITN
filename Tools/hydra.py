import os

from execute_command import execute_command


class Hydra:
    def __init__(self, ip, port, service, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.url = f"hydra://{self.ip}:{self.port}"
        self.service = service
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"Hydra_{self.port}_{self.timestamp}.json")

        if self.service == "ssh" or self.service == "ftp":
            self.wordlist = "ssh-ftp-betterdefaultpasslist.txt"
        elif self.service == "mysql" or self.service == "postgresql" or self.service == "mssql" or self.service == "mongodb" or self.service == "redis" or self.service == "oracle-listener":
            self.wordlist = "dbs-betterdefaultpasslist.txt"
        else:
            self.wordlist = "big.txt"

        self.wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", self.wordlist)

    def run_hydra(self):
        # Code to run Hydra
        cmd = f"hydra -C {self.wordlist_path} -t 1 -s {self.port} {self.ip} {self.service} -o {self.output_file} -b json -I"
        return execute_command(cmd, "Hydra", self.output_file, self.url)