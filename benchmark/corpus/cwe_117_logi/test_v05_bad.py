import logging

def audit(user, verbose):
    if verbose:
        logging.error(user)
    else:
        logging.error("guest")

user = input("u: ")
audit(user, True)
