from flask_wtf import csrf

def transfer_handler():
    return "ok"

handler = csrf.exempt(transfer_handler)
