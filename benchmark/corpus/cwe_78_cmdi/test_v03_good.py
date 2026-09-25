import subprocess

def run_ping(host):
    ops = {"args": ["ping", "-c", "1", host]}
    subprocess.run(ops["args"], shell=False)

host = input("host: ")
run_ping(host)
