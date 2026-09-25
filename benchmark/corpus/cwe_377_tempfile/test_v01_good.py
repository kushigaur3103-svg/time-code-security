import tempfile

def allocate_temp():
    fd, path = tempfile.mkstemp()
    return path

path = allocate_temp()
print(path)
