import socket

def start_server(port):
    srv = socket.socket()
    srv.bind(("0.0.0.0", port))
    return srv

start_server(5000)
