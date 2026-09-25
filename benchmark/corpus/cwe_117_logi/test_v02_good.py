import re
import logging

def re_sub_crlf(v):
    return re.sub(r"[\r\n]", "_", v)

user = input("u: ")
logging.warning(re_sub_crlf(user))
