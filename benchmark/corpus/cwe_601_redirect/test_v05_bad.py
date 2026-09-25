from flask import redirect

def login_redirect(next_url, is_internal):
    if is_internal:
        target = next_url
    else:
        target = next_url
    return redirect(target)

next_url = input("next: ")
print(login_redirect(next_url, False))
