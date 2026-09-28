import sqlite3


def run_lookup(value):
    connection = sqlite3.connect("accounts.db")
    return connection.cursor().execute("SELECT * FROM accounts WHERE token = '" + value + "'")
