import sqlite3


def query_records(term):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM logs WHERE name = '" + term + "'")
