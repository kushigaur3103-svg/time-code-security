import tempfile

spec = {"tmp": tempfile.mktemp(suffix=".tmp"), "owner": "app"}
print(spec["tmp"])
