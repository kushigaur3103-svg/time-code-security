import sqlite3

def execute_user_query(query_string):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query_string)