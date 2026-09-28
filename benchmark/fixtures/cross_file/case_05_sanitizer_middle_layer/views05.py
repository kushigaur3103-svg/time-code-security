import os

from cleaner05 import build_safe


def ping_view(request):
    raw = request.GET.get("ip")
    command = build_safe(raw)
    return os.system(command)
