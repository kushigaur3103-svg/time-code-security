import os

def read_file(filename):
    path = f"/var/app/uploads/{filename}"
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename))
