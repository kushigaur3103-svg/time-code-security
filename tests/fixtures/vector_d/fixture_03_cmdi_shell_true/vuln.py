import subprocess

def ping_host(host_ip):
    cmd = f"ping -c 1 {host_ip}"
    return subprocess.call(cmd, shell=True)
