def execute(data):
    """Name collides with the DB-API cursor method, but performs no query at all."""
    return data.strip()
