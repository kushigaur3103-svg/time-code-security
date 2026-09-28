from repo04 import exec_query as run_q


def report_view(request):
    statement = request.GET.get("sql")
    return run_q(statement)
