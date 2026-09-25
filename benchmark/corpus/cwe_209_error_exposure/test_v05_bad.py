def handle():
    try:
        return load()
    except Exception as e:
        log(e)
        return e
