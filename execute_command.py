import subprocess
from datetime import datetime


def execute_command(command, tool_name, output_file):
    """Execute a command and return results"""

    process: subprocess.Popen | None = None
    try:
        print(f"  Running {tool_name}...")

        # Execute command with timeout
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = process.communicate(timeout=600)  # 10 minute timeout

        result = {
            "tool": tool_name,
            "command": command,
            "output_file": output_file,
            "return_code": process.returncode,
            "timestamp": datetime.now().isoformat(),
            "success": process.returncode == 0
        }

        if process.returncode == 0:
            print(f"    {tool_name} completed successfully")
            result["status"] = "completed"
        elif tool_name == "Nikto" and process.returncode == 1:
            print(f"    {tool_name} completed successfully (vulnerabilities found)")
            result["status"] = "completed"
        else:
            print(f"    {tool_name} failed with return code {process.returncode}")
            result["status"] = "failed"
            result["error"] = stderr

        return result

    except subprocess.TimeoutExpired:
        print(f"    {tool_name} timed out")
        process.kill()
        return {
            "tool": tool_name,
            "command": command,
            "output_file": output_file,
            "status": "timeout",
            "timestamp": datetime.now().isoformat(),
            "success": False
        }
    except FileNotFoundError:
        print(f"    {tool_name} not found. Please install it.")
        return {
            "tool": tool_name,
            "command": command,
            "status": "tool_not_found",
            "timestamp": datetime.now().isoformat(),
            "success": False
        }
    except Exception as e:
        print(f"    Error running {tool_name}: {str(e)}")
        return {
            "tool": tool_name,
            "command": command,
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "success": False
        }