import traceback

def api_response():
    try:
        execute_job()
    except Exception:
        err = traceback.format_exception(*sys.exc_info())
        return {"error_detail": "".join(err)}
