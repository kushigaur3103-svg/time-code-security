import os
from helper import format_command

def execute_ping(request):
    user_input = request.GET.get("ip")
    # Helper se return hokar data tainted rehta hai
    cmd = format_command(user_input)
    os.system(cmd)  # CWE-78: Command Injection