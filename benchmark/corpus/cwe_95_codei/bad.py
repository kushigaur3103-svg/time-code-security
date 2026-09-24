from flask import request

def run_calculation():
    code = request.args.get("expr")
    return eval(code)
