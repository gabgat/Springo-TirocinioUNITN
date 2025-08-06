import datetime

def printerr(message):
    """Prints an error message"""
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] - \033[91m[ERR]  {message}\033[00m")

def printwarn(message):
    """Prints a warning message"""
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] - \033[93m[WAR]  {message}\033[00m")

def printout(message):
    """Prints a normal output/log"""
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] - \033[92m[LOG]  {message}\033[00m")

def printsec(message):
    """Prints a section"""
    print("\n")
    print("\033[1;96m-\033[00m" * 50)
    print(f"\033[1;96m    {message}\033[00m")
    print("\033[1;96m-\033[00m" * 50)