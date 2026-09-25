from werkzeug.utils import secure_filename
import os

UPLOAD_DIR = "/var/app/uploads"

def read_file(filename):
    # Container flow: sanitized path stored in a dict before opening
    safe = {"path": os.path.join(UPLOAD_DIR, secure_filename(filename))}
    with open(safe["path"]) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
