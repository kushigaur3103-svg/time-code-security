import os

UPLOAD_DIR = "/var/app/uploads"

def read_file(filename):
    safe = os.path.basename(filename)
    path = os.path.normpath(os.path.join(UPLOAD_DIR, safe))
    if not path.startswith(UPLOAD_DIR):
        raise ValueError("Path traversal detected")
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
