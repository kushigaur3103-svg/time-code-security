import traceback

def handle_request(req):
    try:
        process(req)
    except Exception:
        return {"status": "error", "stack": traceback.format_exc()}
