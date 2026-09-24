from flask import request

MAX_READ_SIZE = 65536

def receive_stream():
    stream = request.stream
    payload = stream.read(MAX_READ_SIZE)
    return payload
