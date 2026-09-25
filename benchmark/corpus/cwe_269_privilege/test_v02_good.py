import os

old_uid = os.geteuid()
try:
    os.seteuid(0)
    execute_privileged_task()
finally:
    os.seteuid(old_uid)
