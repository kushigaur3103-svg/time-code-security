import subprocess

def build_cmd(host):
    return f"ping -c 1 {host}"

def run_ping(host):
    cmd = build_cmd(host)
    subprocess.run(cmd, shell=True)

host = input("host: ")
run_ping(host)
