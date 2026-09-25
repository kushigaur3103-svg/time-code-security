from telnetlib import Telnet

def connect_remote(target):
    client = Telnet(target)
    return client

connect_remote("192.168.1.1")
