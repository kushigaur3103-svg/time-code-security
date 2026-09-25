def handle():
    try:
        return load()
    except ValueError:
        return "Invalid input"
