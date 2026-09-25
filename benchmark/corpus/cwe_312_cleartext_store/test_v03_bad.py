import sqlite3

username = input("u: ")
password = input("p: ")
conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
