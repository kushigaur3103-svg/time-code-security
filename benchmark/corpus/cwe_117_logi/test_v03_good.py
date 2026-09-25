import logging

user = input("u: ")
entry = {"msg": sanitize_log_input(user)}
logging.info(entry["msg"])
