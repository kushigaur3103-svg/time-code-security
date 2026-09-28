import os

from decorators import log_call


@log_call
def run_command(cmd):
    return os.system("ls " + cmd)


def command_view(request):
    value = request.GET.get("value")
    return run_command(value)
