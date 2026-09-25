from flask import request

def grant():
    if request.args.get("auth") == "1":
        return "granted"
    return "denied"
