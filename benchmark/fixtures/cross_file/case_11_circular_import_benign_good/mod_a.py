from mod_b import run_step

JOB_NAME = "nightly_batch"


def status_view(request):
    label = request.GET.get("label")
    return run_step(JOB_NAME)
