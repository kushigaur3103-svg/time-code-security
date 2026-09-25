import ldap

username = input("u: ")
filter_str = f"(uid={username})"
conn = ldap.initialize("ldap://example.com")
conn.search("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
