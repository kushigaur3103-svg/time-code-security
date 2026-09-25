from flask import make_response
resp = make_response("ok")
resp.set_cookie("track", track_id, samesite=None, secure=False)
