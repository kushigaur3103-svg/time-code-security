import tempfile

path = tempfile.NamedTemporaryFile(suffix=".tmp").name
print(path)
