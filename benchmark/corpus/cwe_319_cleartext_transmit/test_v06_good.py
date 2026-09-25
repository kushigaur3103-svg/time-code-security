import httpx

creds = {"user": "alice", "password": "secret"}
httpx.post("https://api.example.com/token", data=creds)
