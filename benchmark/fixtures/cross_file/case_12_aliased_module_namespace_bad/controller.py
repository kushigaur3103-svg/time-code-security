import service as db_svc


def metrics_view(request):
    key = request.GET.get("key")
    return db_svc.execute_query(key)
