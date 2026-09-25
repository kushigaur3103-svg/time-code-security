import tempfile

p = tempfile.mktemp(dir="/tmp", prefix="app")
print(p)
