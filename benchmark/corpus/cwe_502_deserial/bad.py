from flask import request
import pickle
import base64

def restore_session():
    data = request.cookies.get("session")
    payload = base64.b64decode(data)
    return pickle.loads(payload)
