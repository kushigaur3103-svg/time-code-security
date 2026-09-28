from gateway import gateway_entry


def report_view(request):
    token = request.GET.get("token")
    return gateway_entry(token)
