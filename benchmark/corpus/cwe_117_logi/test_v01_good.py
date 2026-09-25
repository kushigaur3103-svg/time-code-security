import logging

def replace_crlf(value):
    return value.replace("\r", "_").replace("\n", "_")

user = input("u: ")
logging.info(replace_crlf(user))
