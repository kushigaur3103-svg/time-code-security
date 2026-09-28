from fetcher import get_record_id
from repo import query_db


def run_fetch(request):
    val = get_record_id(request)
    return query_db(val)
