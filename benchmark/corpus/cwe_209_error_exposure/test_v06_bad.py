def handle():
    try:
        return load()
    except KeyError as e:
        if e:
            return str(e)
