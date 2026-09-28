from oop_service import AccountService

def account_view(request):
    acc = request.GET.get("account")
    service = AccountService()
    # OOP Instance method call
    return service.fetch_account(acc)