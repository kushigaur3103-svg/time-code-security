def handle():
    try:
        return load()
    except Exception as e:
        return "Internal server error"
