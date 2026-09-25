import os

def protect(path):
    mode = 0o600
    os.chmod(path, mode)

protect("/tmp/app.conf")
