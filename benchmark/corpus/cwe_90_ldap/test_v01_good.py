import ldap
from ldap.filter import escape_filter_chars

username = input("u: ")
safe_user = escape_filter_chars(username)
filter_str = f"(uid={safe_user})"
conn = ldap.initialize("ldap://example.com")
conn.search("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
