def get_untrusted_id(request):
    """Return the identifier exactly as the caller supplied it."""
    return request.GET.get("id")
