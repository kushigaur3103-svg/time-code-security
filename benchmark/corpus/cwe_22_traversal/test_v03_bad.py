import os

def read_file(filename):
    cfg = {"path": f"/var/app/uploads/{filename}"}
    with open(cfg["path"]) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
