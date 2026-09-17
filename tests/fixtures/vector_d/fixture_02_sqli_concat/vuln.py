import sqlite3

def find_order(cursor, order_id):
    query = "SELECT * FROM orders WHERE id = " + str(order_id)
    cursor.execute(query)
    return cursor.fetchall()
