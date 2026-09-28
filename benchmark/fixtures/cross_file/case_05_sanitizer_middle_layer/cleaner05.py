import shlex


def build_safe(value):
    return shlex.quote(value)
