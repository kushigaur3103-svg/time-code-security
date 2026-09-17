import sqlite3

def find_order(cursor, order_id):
    query = "SELECT * FROM orders WHERE id = ?"
    cursor.execute(query, (order_id,))
    return cursor.fetchall()
