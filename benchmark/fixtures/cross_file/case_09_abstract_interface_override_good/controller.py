from service import SafeHandler


def user_view(request):
    user_id = request.GET.get("id")
    handler = SafeHandler()
    return handler.fetch_rows(user_id)
