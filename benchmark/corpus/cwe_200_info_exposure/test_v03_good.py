def handle_request(req):
    try:
        process(req)
    except Exception:
        return {"status": "error", "message": "Failed to process request"}
