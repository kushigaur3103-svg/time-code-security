from django.http import HttpResponse
response = HttpResponse()
response.set_cookie("user_id", user_id, secure=True, httponly=True)
