from flask import request

def read_log():
    log_name = request.args.get("log")
    with open(f"/var/log/{log_name}", "r") as f:
        return f.read(1024)
