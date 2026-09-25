import socket

s = socket.socket()
s.bind(("0.0.0.0", 8080))
s.listen(5)
