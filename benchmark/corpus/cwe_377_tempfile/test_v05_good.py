import tempfile

def make_temp_path(fast):
    if fast:
        fd, p = tempfile.mkstemp()
    else:
        fd, p = tempfile.mkstemp(prefix="slow")
    return p

print(make_temp_path(True))
