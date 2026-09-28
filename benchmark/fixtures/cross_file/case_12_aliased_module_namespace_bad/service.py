import sqlite3


def execute_query(statement):
    connection = sqlite3.connect("metrics.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT * FROM metrics WHERE key = '" + statement + "'")
