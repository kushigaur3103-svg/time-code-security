import ldap

role = input("r: ")
f = "(&(objectClass=person)(role={}))".format(role)
conn = ldap.initialize("ldap://example.com")
conn.search_st("dc=com", ldap.SCOPE_SUBTREE, f, timeout=10)
