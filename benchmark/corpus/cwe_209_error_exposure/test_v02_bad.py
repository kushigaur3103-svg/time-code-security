def handle():
    try:
        return load()
    except ValueError as err:
        return repr(err)
