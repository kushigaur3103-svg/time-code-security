import shlex

def format_command(raw_input):
    # Safe sanitizer: shell escape kar diya
    return shlex.quote(raw_input)