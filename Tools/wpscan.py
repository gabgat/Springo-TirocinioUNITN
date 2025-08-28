import os
import subprocess
from dotenv import load_dotenv

from execute_command import execute_command
from printer import printout, printerr

class WPScan:
    def __init__(self, url, port, tools_dir, timestamp):

        load_dotenv()
        self.WPSCAN_API_KEY = os.getenv("WPSCAN_API_KEY")

        self.url = url
        self.port = port
        self.timestamp = timestamp
        self.output_file = os.path.join(tools_dir, f"wpscan_{self.port}_{self.timestamp}.json")


    def run_wpscan(self):
        """Run WPScan WordPress website vulnerability scanner"""
        # Update WPScan Database
        try:
            printout("Updating WPScan DB...")
            subprocess.run(["wpscan", "--update"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            printerr("WPScan DB update failed.")

        #Check if website is WordPress (no waste of tokens)
        if subprocess.run(["wpscan", "--url", self.url],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            printout(f"{self.url} is not a WordPress website")
            return None

        cmd = f"wpscan --url {self.url} -e ap,vt,tt,cb,dbe,u,m --plugins-detection aggressive --api-token {self.WPSCAN_API_KEY} -f json -o {self.output_file}"

        return execute_command(cmd, "Wpscan", self.output_file, self.url)