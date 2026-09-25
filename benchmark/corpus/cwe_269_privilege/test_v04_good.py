import os

def init_service(target_uid):
    start_web_server()
    os.setuid(target_uid)

init_service(1000)
