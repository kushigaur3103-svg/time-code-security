import httpx

creds = ("user", input("p: "))
httpx.get("https://api.backend.net/users", auth=creds)
