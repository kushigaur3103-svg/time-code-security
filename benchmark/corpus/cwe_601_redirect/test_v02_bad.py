from flask import redirect

def resolve_target(next_url):
    return next_url  # passes through unvalidated

def login_redirect(next_url):
    target = resolve_target(next_url)
    return redirect(target)

next_url = input("next: ")
print(login_redirect(next_url))
