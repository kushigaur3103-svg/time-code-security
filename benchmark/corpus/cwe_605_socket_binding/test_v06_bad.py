import socket

s = socket.socket(socket.AF_INET6)
s.bind(("::", 8080))
