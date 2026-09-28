ROWS_BY_LABEL = {}


def fetch_count(label):
    return len(ROWS_BY_LABEL.get(label, []))
