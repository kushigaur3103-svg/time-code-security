def run_input(user_input, is_trusted):
    if is_trusted:
        result = eval(user_input)
    else:
        result = eval(user_input)  # still unsafe in both branches
    return result

user_input = input("expr: ")
print(run_input(user_input, False))
