from flask import request

def receive_stream():
    stream = request.stream
    payload = stream.read()
    return payload
