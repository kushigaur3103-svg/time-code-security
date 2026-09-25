import socket

MAX_READ = 65536

def handle_client(sock):
    buf = {"data": sock.makefile().read(MAX_READ)}
    return buf["data"]

srv = socket.socket()
srv.bind(("0.0.0.0", 9997))
srv.listen(1)
conn, _ = srv.accept()
print(handle_client(conn))
