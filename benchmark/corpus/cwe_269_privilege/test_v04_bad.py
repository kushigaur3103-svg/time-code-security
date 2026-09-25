import os

def init_service():
    os.setuid(0)
    start_web_server()

init_service()
