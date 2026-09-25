import subprocess
import re

def run_ping(host):
    if not re.match(r"^[a-zA-Z0-9.\-]+$", host):
        raise ValueError("Invalid host")
    subprocess.run(["ping", "-c", "1", host], shell=False)

host = input("host: ")
run_ping(host)
