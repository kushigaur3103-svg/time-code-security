import subprocess

class Pinger:
    def __init__(self, host):
        self.cmd = f"ping -c 1 {host}"

    def execute(self):
        subprocess.run(self.cmd, shell=True)

host = input("host: ")
Pinger(host).execute()
