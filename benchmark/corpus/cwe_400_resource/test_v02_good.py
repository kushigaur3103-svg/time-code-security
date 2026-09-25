import socket

MAX_READ = 65536

def receive_all(sock):
    f = sock.makefile()
    return f.read(MAX_READ)

def handle_client(sock):
    data = receive_all(sock)
    return data

srv = socket.socket()
srv.bind(("0.0.0.0", 9998))
srv.listen(1)
conn, _ = srv.accept()
print(handle_client(conn))
