import os

def build_path(filename):
    return f"/var/app/uploads/{filename}"

def read_file(filename):
    path = build_path(filename)
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
