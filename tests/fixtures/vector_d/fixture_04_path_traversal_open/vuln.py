import os

def read_uploaded_file(base_dir, filename):
    target_path = base_dir + filename
    with open(target_path, "r") as f:
        return f.read()
