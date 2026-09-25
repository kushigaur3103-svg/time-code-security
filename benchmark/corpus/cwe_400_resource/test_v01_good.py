import socket

MAX_READ = 65536

def read_from_client(sock):
    data = sock.makefile().read(MAX_READ)
    return data

srv = socket.socket()
srv.bind(("0.0.0.0", 9999))
srv.listen(1)
conn, _ = srv.accept()
print(read_from_client(conn))
