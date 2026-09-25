import socket

MAX_READ = 65536

def handle_client(sock, binary):
    if binary:
        data = sock.makefile("rb").read(MAX_READ)
    else:
        data = sock.makefile().read(MAX_READ)
    return data

srv = socket.socket()
srv.bind(("0.0.0.0", 9995))
srv.listen(1)
conn, _ = srv.accept()
print(handle_client(conn, False))
