from repo06 import load_report


def export_view(request):
    label = request.GET.get("label")
    return load_report("sales_summary_2026")
