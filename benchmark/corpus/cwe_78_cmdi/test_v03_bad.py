import subprocess

def run_ping(host):
    ops = {"cmd": f"ping -c 1 {host}"}
    subprocess.run(ops["cmd"], shell=True)

host = input("host: ")
run_ping(host)
