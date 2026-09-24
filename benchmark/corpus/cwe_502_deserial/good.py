from flask import request
import json
import base64

def restore_session():
    data = request.cookies.get("session")
    payload = base64.b64decode(data).decode("utf-8")
    return json.loads(payload)
