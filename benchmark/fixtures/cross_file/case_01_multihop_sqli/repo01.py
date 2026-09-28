import sqlite3


def fetch_row(name):
    connection = sqlite3.connect("reporting.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM profiles WHERE name = '" + name + "'")
