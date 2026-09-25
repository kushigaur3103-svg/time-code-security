import traceback

def handle():
    try:
        return load()
    except OSError:
        return traceback.format_exc()
