from danger07 import *
from safe07 import fetch_count


def stats_view(request):
    label = request.GET.get("label")
    return fetch_count(label)
