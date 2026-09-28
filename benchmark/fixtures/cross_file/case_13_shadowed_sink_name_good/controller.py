import local_lib


def preview_view(request):
    payload = request.GET.get("payload")
    return local_lib.execute(payload)
