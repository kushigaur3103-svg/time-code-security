import logging

def audit(user, verbose):
    msg = sanitize_log_input(user)
    if verbose:
        logging.info(msg)
    else:
        logging.error(msg)

user = input("u: ")
audit(user, True)
