import logging

def build_log_msg(u):
    return f"user={u}"

user = input("u: ")
logging.error(build_log_msg(user))
