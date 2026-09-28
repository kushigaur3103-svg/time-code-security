from db_mod import query_records
from os_mod import run_tool


def dashboard_view(request):
    user_input = request.GET.get("q")
    rows = query_records(user_input)
    report = run_tool(user_input)
    return rows, report
