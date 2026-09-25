import os

UPLOAD_DIR = "/var/app/uploads"

def read_file(filename, binary):
    sub = "bin" if binary else "txt"
    base_dir = os.path.join(UPLOAD_DIR, sub)
    path = os.path.normpath(os.path.join(base_dir, os.path.basename(filename)))
    if not path.startswith(base_dir):
        raise ValueError("Blocked")
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename, False))
