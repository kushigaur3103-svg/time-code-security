import socket

host = "::1"
s = socket.socket(socket.AF_INET6)
s.bind((host, 3000))
