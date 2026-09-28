from functools import wraps


def validated(func):
    """Validation decorator: the view only ever sees an integer identifier."""

    @wraps(func)
    def wrapper(record_id):
        return func(int(record_id))

    return wrapper
