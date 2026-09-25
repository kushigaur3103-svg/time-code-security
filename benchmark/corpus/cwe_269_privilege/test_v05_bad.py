import os

def run_cmd():
    os.seteuid(0)
    return os.system("whoami")

run_cmd()
