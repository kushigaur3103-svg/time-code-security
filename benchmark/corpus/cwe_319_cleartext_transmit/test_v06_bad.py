import httpx

creds = {"user": "alice", "password": "secret"}
httpx.post("http://api.example.com/token", data=creds)
