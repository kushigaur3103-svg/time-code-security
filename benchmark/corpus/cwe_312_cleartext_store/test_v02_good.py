import bcrypt

password = input("p: ")
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
conn.execute("INSERT INTO users (password) VALUES (?)", (hashed,))
