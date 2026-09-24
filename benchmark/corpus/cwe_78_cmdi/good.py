from flask import request
import subprocess

def run_backup():
    filename = request.args.get("filename")
    subprocess.run(["tar", "-czf", "backup.tar.gz", filename], shell=False)
