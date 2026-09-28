import subprocess


def launch(command):
    return subprocess.run(command, shell=True)
