import json
import os

from printer import printerr, printout


def load(filename):
    try:
        with open(filename) as f:
            temp = json.load(f)
            printout(f"{filename} JSON loaded successfully")

            return temp

    except FileNotFoundError:
        printerr("Error: JSON file not found")
    except json.JSONDecodeError:
        printerr("Error: Invalid JSON format")
    except Exception as e:
        printerr(f"An unexpected error occurred: {e}")


class ResultParser:
    def __init__(self, output_dir):
        self.results = {}
        self.tools_dir = f"{output_dir}/tools"

    def start(self):
        try:
            files = [f for f in os.listdir(self.tools_dir) if f.endswith('.json')]
        except OSError as e:
            printerr(f"Error reading directory {self.tools_dir}: {e}")
            return

        for file in files:
            printout(f"Loading {file}")
            parts = file.split('_')
            if len(parts) >= 2:
                tool_name = parts[0]
                if tool_name == "nmap":
                    port = "0"
                else:
                    port = parts[1]



                if tool_name not in self.results:
                    self.results[tool_name] = {}

                data = load(f"{self.tools_dir}/{file}")

                if data is not None:
                    self.results[tool_name][port] = data

            else:
                printerr(f"Cannot parse {file}")

        return self.results