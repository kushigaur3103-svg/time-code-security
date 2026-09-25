import os

UPLOAD_DIR = "/var/app/uploads"

def read_file(filename):
    path = os.path.normpath(os.path.join(UPLOAD_DIR, os.path.basename(filename)))
    if not path.startswith(UPLOAD_DIR):
        raise ValueError("Traversal blocked")
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
