import os

def protect(path, owner_only):
    if owner_only:
        os.chmod(path, 0o600)
    else:
        os.chmod(path, 0o700)

protect("/tmp/app.conf", True)
