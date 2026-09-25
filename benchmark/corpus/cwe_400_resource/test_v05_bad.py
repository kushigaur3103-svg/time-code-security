import socket

def handle_client(sock, binary):
    if binary:
        data = sock.makefile("rb").read()
    else:
        data = sock.makefile().read()
    return data

srv = socket.socket()
srv.bind(("0.0.0.0", 9995))
srv.listen(1)
conn, _ = srv.accept()
print(handle_client(conn, False))
