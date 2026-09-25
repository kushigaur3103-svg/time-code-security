import socket

s = socket.socket(socket.AF_INET6)
s.bind(("::1", 8080))
