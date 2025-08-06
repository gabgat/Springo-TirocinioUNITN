import subprocess
from datetime import datetime
from printer import printerr, printwarn, printout


def execute_command(command, tool_name, output_file, url):
    """Execute a command and return results"""

    process: subprocess.Popen | None = None
    try:
        printout(f"Running {tool_name} for {url}...")

        # Execute command with timeout
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = process.communicate()#(timeout=3600)

        result = {
            "tool": tool_name,
            "command": command,
            "output_file": output_file,
            "return_code": process.returncode,
            "timestamp": datetime.now().isoformat(),
            "success": process.returncode == 0,
            "output": stdout
        }

        if process.returncode == 0:
            printout(f"{tool_name} for {url} completed successfully")
            result["status"] = "completed"
        elif tool_name == "Nikto" and process.returncode == 1:
            printout(f"{tool_name} for {url} completed successfully (vulnerabilities found)")
            result["status"] = "completed"
        elif tool_name == "SSH Audit" and process.returncode == 3:
            printout(f"{tool_name} for {url} completed successfully")
            result["status"] = "completed"
        else:
            printwarn(f"{tool_name} for {url} failed with return code {process.returncode}")
            result["status"] = "failed"
            result["error"] = stderr

        return result

    except subprocess.TimeoutExpired:
        printwarn(f"{tool_name} for {url} timed out")
        process.kill()
        return {
            "tool": tool_name,
            "command": command,
            "output_file": output_file,
            "status": "timeout",
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "output": None
        }
    except FileNotFoundError:
        printerr(f"{tool_name} not found. Please install it.")
        return {
            "tool": tool_name,
            "command": command,
            "status": "tool_not_found",
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "output": None
        }
    except Exception as e:
        printerr(f"Error running {tool_name} for {url}: {str(e)}")
        return {
            "tool": tool_name,
            "command": command,
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "output": None
        }