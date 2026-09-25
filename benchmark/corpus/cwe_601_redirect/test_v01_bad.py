from flask import redirect

def login_redirect(next_url):
    return redirect(next_url)

next_url = input("next: ")
print(login_redirect(next_url))
