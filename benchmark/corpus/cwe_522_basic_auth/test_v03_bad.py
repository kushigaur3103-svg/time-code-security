import httpx

creds = ("user", input("p: "))
httpx.get("http://api.backend.net/users", auth=creds)
