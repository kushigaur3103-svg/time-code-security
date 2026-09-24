from flask import request
from werkzeug.utils import secure_filename
import os

def read_log():
    log_name = request.args.get("log")
    safe_name = secure_filename(log_name)
    file_path = os.path.join("/var/log", safe_name)
    with open(file_path, "r") as f:
        return f.read(1024)
