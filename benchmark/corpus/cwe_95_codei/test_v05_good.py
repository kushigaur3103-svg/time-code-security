import ast

def run_input(user_input, is_trusted):
    if is_trusted:
        result = ast.literal_eval(user_input)
    else:
        result = ast.literal_eval(user_input)
    return result

user_input = input("expr: ")
print(run_input(user_input, False))
