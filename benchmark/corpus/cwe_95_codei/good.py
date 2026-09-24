from flask import request
import ast

def run_calculation():
    code = request.args.get("expr")
    return ast.literal_eval(code)
