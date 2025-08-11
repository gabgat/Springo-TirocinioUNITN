import os

from execute_command import execute_command

class FFUF:
    def __init__(self, url, port, tools_dir, timestamp, threads):
        self.url = url
        self.port = port
        self.tools_dir = tools_dir
        self.timestamp = timestamp
        self.threads = threads
        self.extensions = [
            ".asp",
            ".aspx",
            ".bat",
            ".c",
            ".cfm",
            ".cgi",
            ".css",
            ".com",
            ".dll",
            ".exe",
            ".hta",
            ".htm",
            ".html",
            ".inc",
            ".jhtml",
            ".js",
            ".jsa",
            ".json",
            ".jsp",
            ".log",
            ".mdb",
            ".nsf",
            ".pcap",
            ".php",
            ".php2",
            ".php3",
            ".php4",
            ".php5",
            ".php6",
            ".php7",
            ".phps",
            ".pht",
            ".phtml",
            ".pl",
            ".phar",
            ".rb",
            ".reg",
            ".sh",
            ".shtml",
            ".sql",
            ".swf",
            ".txt",
            ".xml"
        ]
        self.response = ["200", "204", "301", "302", "307", "401", "403"]
        self.wordlist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Wordlists", "big.txt")
        self.output_file = os.path.join(self.tools_dir, f"ffuf_{self.port}_{self.timestamp}.json")

    def run_ffuf(self):
        """Run FFUF directory enumeration"""

        #cmd = f"ffuf -w {self.wordlist}:FUZZ -u {self.url}/FUZZ -recursion -e {','.join(self.extensions)} -mc {','.join(self.response)} -ac -ic -v -t {self.threads} -o {self.output_file}"
        #FOR TESTING USE THIS:
        cmd = f"ffuf -w {self.wordlist}:FUZZ -u {self.url}/FUZZ -recursion -recursion-depth 2 -e {','.join(self.extensions)} -mc {','.join(self.response)} -ac -ic -t {self.threads} -json -o {self.output_file}"

        return execute_command(cmd, "FFUF", self.output_file, self.url)