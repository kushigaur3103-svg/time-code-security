from service01 import load_profile


def profile_view(request):
    name = request.GET.get("name")
    return load_profile(name)
