from accounts03 import UserService


def account_view(request):
    token = request.GET.get("token")
    service = UserService()
    return service.search(token)
