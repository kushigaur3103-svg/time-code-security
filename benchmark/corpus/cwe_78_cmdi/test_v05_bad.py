import subprocess

def run_diagnostic(host, verbose):
    if verbose:
        cmd = f"ping -v -c 3 {host}"
    else:
        cmd = f"ping -c 1 {host}"
    subprocess.run(cmd, shell=True)

host = input("host: ")
run_diagnostic(host, False)
