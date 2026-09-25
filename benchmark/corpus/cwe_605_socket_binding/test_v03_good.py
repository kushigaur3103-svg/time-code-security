import socket

def start_server(port):
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    return srv

start_server(5000)
