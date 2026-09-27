from ast_scanner import TaintTracker
src = '''import subprocess
def test(domain):
    command = "dig {}".format(domain)
    subprocess.Popen(command, shell=True)
'''
_, sinks, _ = TaintTracker(source=src, file_path="test_format.py").analyze()
print("Findings:", [s.metadata.get("cwe") for s in sinks if s.metadata.get("cwe") == "CWE-78"])
