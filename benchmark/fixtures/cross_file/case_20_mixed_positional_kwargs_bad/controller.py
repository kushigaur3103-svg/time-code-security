from service import step1


def chain_view(request):
    user_input = request.GET.get("value")
    return step1(user_input)
