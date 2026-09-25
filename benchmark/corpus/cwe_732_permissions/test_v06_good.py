import os

path = "/tmp/app.conf"
os.chmod(path, 0o700 & 0o400)
