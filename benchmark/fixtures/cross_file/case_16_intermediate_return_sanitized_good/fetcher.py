def get_record_id(request):
    """Convert the raw identifier so only an integer can reach the query."""
    raw_id = request.GET.get("id")
    return int(raw_id)
