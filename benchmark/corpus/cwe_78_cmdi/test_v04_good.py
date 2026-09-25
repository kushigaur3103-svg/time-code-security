import subprocess

class Pinger:
    def __init__(self, host):
        self.host = host

    def execute(self):
        subprocess.run(["ping", "-c", "1", self.host], shell=False)

host = input("host: ")
Pinger(host).execute()
