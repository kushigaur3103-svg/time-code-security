def handle():
    try:
        return load()
    except Exception as e:
        print(type(e).__name__)
        return "Error handled"
