import logging

def api_response():
    try:
        execute_job()
    except Exception:
        logging.exception("Job failure")
        return {"error_detail": "Operation failed"}
