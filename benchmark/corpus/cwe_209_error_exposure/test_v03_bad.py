def handle():
    try:
        return load()
    except RuntimeError as e:
        return e
