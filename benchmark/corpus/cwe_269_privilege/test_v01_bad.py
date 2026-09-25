import os

def elevate():
    os.setuid(0)
    do_untrusted_work()

elevate()
