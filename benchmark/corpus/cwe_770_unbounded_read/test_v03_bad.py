from flask import request

def get_upload_content():
    return request.stream.read()
