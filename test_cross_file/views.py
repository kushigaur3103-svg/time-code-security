from db_service import execute_user_query

def search_view(request):
    user_search = request.GET.get("q")
    execute_user_query(user_search)