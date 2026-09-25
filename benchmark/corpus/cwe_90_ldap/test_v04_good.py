import ldap

ALLOWED_ROLES = {"admin", "editor", "viewer"}
role = input("r: ")
if role in ALLOWED_ROLES:
    f = "(&(objectClass=person)(role={}))".format(role)
    conn = ldap.initialize("ldap://example.com")
    conn.search_st("dc=com", ldap.SCOPE_SUBTREE, f, timeout=10)
