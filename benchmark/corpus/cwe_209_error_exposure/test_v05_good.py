def handle():
    try:
        return load()
    except Exception:
        return "Try again later"
