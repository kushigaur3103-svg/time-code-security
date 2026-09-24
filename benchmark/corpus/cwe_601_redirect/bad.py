from flask import request, redirect

def auth_callback():
    target = request.args.get("next")
    return redirect(target)
