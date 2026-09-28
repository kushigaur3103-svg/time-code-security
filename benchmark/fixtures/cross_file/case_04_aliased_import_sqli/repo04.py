import sqlite3


def exec_query(statement):
    connection = sqlite3.connect("reporting.db")
    return connection.cursor().execute(statement)
