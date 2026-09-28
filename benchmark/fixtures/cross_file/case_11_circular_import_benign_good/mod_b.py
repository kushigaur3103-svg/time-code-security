import subprocess

from mod_a import JOB_NAME


def run_step(job_name):
    return subprocess.run("systemctl status " + job_name, shell=True)


def describe_job():
    return JOB_NAME
