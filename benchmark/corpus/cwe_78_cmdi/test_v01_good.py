import subprocess

def run_ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)

host = input("host: ")
run_ping(host)
