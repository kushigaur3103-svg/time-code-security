from decorators import validated
from repo import query_db


@validated
def detail_view(record_id):
    return query_db(record_id)


def search_view(request):
    raw_id = request.GET.get("id")
    return detail_view(raw_id)
