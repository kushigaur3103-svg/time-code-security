import ldap
from ldap.filter import escape_filter_chars

def find_user(conn, user):
    search_filter = "(cn=%s)" % escape_filter_chars(user)
    return conn.search_s("ou=users,dc=com", ldap.SCOPE_SUBTREE, search_filter)

user = input("user: ")
find_user(conn, user)
