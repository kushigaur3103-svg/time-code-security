import os

def protect(path):
    mode = 0o666
    os.chmod(path, mode)

protect("/tmp/app.conf")
