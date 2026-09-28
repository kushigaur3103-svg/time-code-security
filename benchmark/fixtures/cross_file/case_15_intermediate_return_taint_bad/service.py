from fetcher import get_untrusted_id
from repo import query_db


def run_fetch(request):
    val = get_untrusted_id(request)
    return query_db(val)
