import os

def read_file(filename, binary):
    if binary:
        path = f"/var/app/uploads/bin/{filename}"
    else:
        path = f"/var/app/uploads/txt/{filename}"
    with open(path) as f:
        return f.read()

filename = input("filename: ")
print(read_file(filename, False))
