import tempfile

def make_temp_path(fast):
    if fast:
        p = tempfile.mktemp()
    else:
        p = tempfile.mktemp(prefix="slow")
    return p

print(make_temp_path(True))
