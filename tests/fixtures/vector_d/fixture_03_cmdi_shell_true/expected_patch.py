import subprocess

def ping_host(host_ip):
    cmd_list = ["ping", "-c", "1", host_ip]
    return subprocess.call(cmd_list, shell=False)
