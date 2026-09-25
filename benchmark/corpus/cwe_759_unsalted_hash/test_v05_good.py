from django.contrib.auth.hashers import make_password

password = input("p: ")
hashed = make_password(password)
