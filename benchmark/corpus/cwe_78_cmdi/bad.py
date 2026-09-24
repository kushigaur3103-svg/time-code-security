from flask import request
import subprocess

def run_backup():
    filename = request.args.get("filename")
    command = f"tar -czf backup.tar.gz {filename}"
    subprocess.run(command, shell=True)
