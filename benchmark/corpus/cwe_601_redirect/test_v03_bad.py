from flask import redirect

def login_redirect(next_url):
    routes = {"target": next_url}
    return redirect(routes["target"])

next_url = input("next: ")
print(login_redirect(next_url))
