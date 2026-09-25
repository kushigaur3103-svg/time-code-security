import tempfile

def allocate_temp():
    return tempfile.mktemp()

path = allocate_temp()
print(path)
