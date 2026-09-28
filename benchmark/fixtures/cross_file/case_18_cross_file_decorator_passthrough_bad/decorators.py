import os
import time
from functools import wraps


def log_call(func):
    """Passthrough decorator: it times the call and forwards every argument untouched."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        started = time.perf_counter()
        result = func(*args, **kwargs)
        print(f"{func.__name__} finished in {time.perf_counter() - started:.4f}s")
        return result

    return wrapper
