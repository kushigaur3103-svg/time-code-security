import paramiko

def connect_remote(target):
    client = paramiko.SSHClient()
    client.connect(target, username="admin")
    return client

connect_remote("192.168.1.1")
