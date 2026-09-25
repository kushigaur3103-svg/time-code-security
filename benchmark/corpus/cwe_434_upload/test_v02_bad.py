import os

def dest(name):
    return os.path.join(UPLOAD_DIR, name)

filename = input("f: ")
file.save(dest(filename))
