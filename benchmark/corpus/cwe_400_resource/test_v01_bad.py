import socket

def read_from_client(sock):
    data = sock.makefile().read()  # unbounded read from network
    return data

srv = socket.socket()
srv.bind(("0.0.0.0", 9999))
srv.listen(1)
conn, _ = srv.accept()
print(read_from_client(conn))
