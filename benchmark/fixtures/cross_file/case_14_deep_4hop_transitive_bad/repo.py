import sqlite3


def repo_fetch(token):
    connection = sqlite3.connect("archive.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM archive WHERE token = '" + token + "'")
