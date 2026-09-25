import subprocess

def run_ping(host):
    subprocess.run(f"ping -c 1 {host}", shell=True)

host = input("host: ")
run_ping(host)
