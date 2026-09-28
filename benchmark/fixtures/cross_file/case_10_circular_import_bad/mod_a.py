from mod_b import process_step

DEFAULT_TARGET = "localhost"


def ping_view(request):
    host = request.GET.get("host")
    return process_step(host)
