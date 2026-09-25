def handle():
    try:
        return load()
    except Exception as e:
        return "Contact support"
