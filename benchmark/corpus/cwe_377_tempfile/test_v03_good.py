import tempfile

fd, path = tempfile.mkstemp(suffix=".tmp")
print(path)
