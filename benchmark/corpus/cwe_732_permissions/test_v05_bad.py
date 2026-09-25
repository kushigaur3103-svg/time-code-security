import os

def protect(path, world_readable):
    if world_readable:
        os.chmod(path, 0o644)
    else:
        os.chmod(path, 0o666)

protect("/tmp/app.conf", True)
