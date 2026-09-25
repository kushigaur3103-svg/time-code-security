import os

def run_cmd(orig):
    try:
        os.seteuid(0)
        perform_action()
    finally:
        os.seteuid(orig)

run_cmd(1001)
