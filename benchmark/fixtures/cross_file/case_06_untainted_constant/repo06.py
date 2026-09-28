import sqlite3


def load_report(kind):
    connection = sqlite3.connect("reporting.db")
    return connection.cursor().execute("SELECT * FROM reports WHERE kind = '" + kind + "'")
