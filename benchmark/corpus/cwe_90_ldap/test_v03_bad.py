import ldap

def find_user(conn, user):
    search_filter = "(cn=%s)" % user
    return conn.search_s("ou=users,dc=com", ldap.SCOPE_SUBTREE, search_filter)

user = input("user: ")
find_user(conn, user)
