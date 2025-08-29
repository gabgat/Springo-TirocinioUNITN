import json
import os

from printer import printerr, printout


def load(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            temp = json.load(f)
            printout(f"{filename} JSON loaded successfully")
            return temp

    except FileNotFoundError:
        printerr(f"Error: JSON file not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        printerr(f"Error: Invalid JSON format in {filename}: {e}")
        return None
    except Exception as e:
        printerr(f"An unexpected error occurred while loading {filename}: {e}")
        return None


class ResultParser:
    def __init__(self, output_dir):
        self.results = {}
        self.tools_dir = os.path.join(output_dir, "tools")

    def start(self):
        if not os.path.exists(self.tools_dir):
            printerr(f"Error: Directory {self.tools_dir} does not exist")
            return None

        try:
            files = [f for f in os.listdir(self.tools_dir) if f.endswith('.json')]
        except OSError as e:
            printerr(f"Error reading directory {self.tools_dir}: {e}")
            return None

        if not files:
            printout("No JSON files found in tools directory")
            return self.results

        for file in files:
            printout(f"Loading {file}")

            # Parse filename to extract tool and port
            parts = file.replace('.json', '').split('_')
            if len(parts) >= 2:
                tool_name = parts[0]

                # Special case for nmap which uses port "0"
                if tool_name == "nmap":
                    port = "0"
                else:
                    port = parts[1]

                if tool_name not in self.results:
                    self.results[tool_name] = {}

                file_path = os.path.join(self.tools_dir, file)
                data = load(file_path)

                if data is not None:
                    self.results[tool_name][port] = data
                else:
                    printerr(f"Failed to load data from {file}")

            else:
                printerr(f"Cannot parse filename {file}: expected format 'tool_port.json'")

        return self.results