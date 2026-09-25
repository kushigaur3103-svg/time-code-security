import logging

user = input("u: ")
logging.info("login event: %s", sanitize_log_input(user))
