import socket

s = socket.socket()
s.connect(("example.com", 80))
data = s.recv()
