import os


def run_tool(term):
    return os.system("grep " + term + " /var/log/app.log")
