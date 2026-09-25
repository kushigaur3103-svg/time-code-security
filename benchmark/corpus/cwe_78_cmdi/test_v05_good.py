import subprocess

def run_diagnostic(host, verbose):
    args = ["ping", "-c", "3" if verbose else "1", host]
    subprocess.run(args, shell=False)

host = input("host: ")
run_diagnostic(host, False)
