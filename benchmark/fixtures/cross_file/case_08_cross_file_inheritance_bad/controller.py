from service import UserService


def audit_view(request):
    entry = request.GET.get("entry")
    repository = UserService()
    return repository.fetch_rows(entry)
