import socket

s = socket.socket()
s.bind(("127.0.0.1", 8080))
s.listen(5)
