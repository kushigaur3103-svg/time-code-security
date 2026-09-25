import os

def elevate():
    orig_uid = os.getuid()
    try:
        os.setuid(0)
        do_privileged_setup()
    finally:
        os.setuid(orig_uid)

elevate()
