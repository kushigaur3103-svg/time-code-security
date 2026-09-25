import socket

MAX_READ = 65536

class ClientHandler:
    def __init__(self, sock):
        self.sock = sock

    def read_all(self):
        return self.sock.makefile().read(MAX_READ)

srv = socket.socket()
srv.bind(("0.0.0.0", 9996))
srv.listen(1)
conn, _ = srv.accept()
print(ClientHandler(conn).read_all())
