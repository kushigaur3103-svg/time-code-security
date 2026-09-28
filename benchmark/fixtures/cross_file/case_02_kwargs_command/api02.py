from shell02 import launch


def tool_view(request):
    command = request.POST.get("cmd")
    return launch(command=command)
