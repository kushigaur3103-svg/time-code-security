from user_service import get_profile_data

def search_user(request):
    user_input = request.GET.get("user")
    # Multi-hop call: controller -> service -> repo
    data = get_profile_data(user_input)
    return data