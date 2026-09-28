import sqlite3


def fetch_count(label):
    connection = sqlite3.connect("legacy.db")
    return connection.cursor().execute("SELECT * FROM events WHERE label = '" + label + "'")
