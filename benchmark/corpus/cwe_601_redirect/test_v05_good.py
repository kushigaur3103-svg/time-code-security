from urllib.parse import urlparse

def login_redirect(next_url, is_internal):
    parsed = urlparse(next_url)
    if is_internal:
        target = next_url if not (parsed.scheme or parsed.netloc) else "/"
    else:
        target = "/"
    print(f"Location: {target}")

next_url = input("next: ")
login_redirect(next_url, False)
