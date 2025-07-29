import os

from execute_command import execute_command


class Hydra:
    def __init__(self, ip, port, service, tools_dir, timestamp):
        self.ip = ip
        self.port = port
        self.service = service
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"Hydra_{self.port}_{self.timestamp}.txt")

        if self.service == "ssh" or self.service == "ftp":
            self.wordlist = "ssh-betterdefaultpasslist.txt"

        self.wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", self.wordlist)

    def run_hydra(self):
        # Code to run Hydra
        cmd = f"hydra -C {self.wordlist_path} -t 1 {self.ip} {self.service} -o {self.output_file}"
        return execute_command(cmd, "Hydra", self.output_file)