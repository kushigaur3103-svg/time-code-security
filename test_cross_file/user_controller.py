from user_service import get_profile_data

def search_user(request):
    user_input = request.GET.get("user")
    # Positional ki jagah explicitly keyword argument pass kiya
    data = get_profile_data(username=user_input)
    return data