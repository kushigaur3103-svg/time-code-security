import tempfile

fd, path = tempfile.mkstemp(prefix="app")
print(path)
