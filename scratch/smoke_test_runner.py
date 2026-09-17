import os, sys, time, hashlib, subprocess, shutil
from pathlib import Path

REPO_ROOT = Path(r'c:\Users\aarti gaur\OneDrive\Desktop\time code security')
SMOKE_DIR = REPO_ROOT / 'scratch' / 'live_smoke_repo'
TCS_CLI = REPO_ROOT / 'tcs_cli.py'

def reset_smoke_repo():
    if SMOKE_DIR.exists():
        shutil.rmtree(SMOKE_DIR)
    SMOKE_DIR.mkdir(parents=True, exist_ok=True)
    
    auth_code = '''import sqlite3

def authenticate_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
'''
    runner_code = '''import subprocess

def run_service_check(host):
    cmd = f"ping -c 1 {host}"
    subprocess.call(cmd, shell=True)
'''
    storage_code = '''def read_storage_file(filename):
    base_dir = "/var/data/storage"
    target_path = base_dir + "/" + filename
    with open(target_path, "r") as f:
        return f.read()
'''
    (SMOKE_DIR / 'service_auth.py').write_text(auth_code, encoding='utf-8')
    (SMOKE_DIR / 'service_runner.py').write_text(runner_code, encoding='utf-8')
    (SMOKE_DIR / 'service_storage.py').write_text(storage_code, encoding='utf-8')

def hash_files():
    return {
        f.name: hashlib.sha256(f.read_bytes()).hexdigest()
        for f in sorted(SMOKE_DIR.glob('*.py'))
    }

def run_cmd(args):
    t0 = time.perf_counter()
    env = dict(os.environ)
    env['PYTHONPATH'] = str(REPO_ROOT)
    p = subprocess.run([sys.executable, str(TCS_CLI)] + args, capture_output=True, text=True, cwd=str(REPO_ROOT), env=env)
    t1 = time.perf_counter()
    return p, (t1 - t0) * 1000

print('======================================================================')
print('LIVE REPOSITORY SMOKE TEST & BENCHMARK SUITE')
print('======================================================================\n')

# 1. SETUP
reset_smoke_repo()
initial_hashes = hash_files()
print('[1] Target repository initialized at scratch/live_smoke_repo/:')
for name, h in initial_hashes.items():
    print(f'    * {name} (sha256: {h[:16]}...)')

# 2. EXECUTION PASS 1: SAFE PREVIEW (--fix)
print('\n[2] Executing Pass 1: Safe Preview (--fix)...')
p1, p1_time = run_cmd(['scratch/live_smoke_repo/', '--audit-all', '--fix'])
p1_hashes = hash_files()

print(f'    * Exit Code:    {p1.returncode} (Expected: 1)')
print(f'    * Duration:     {p1_time:.2f} ms ({p1_time/1000:.3f} s)')
print(f'    * Byte-Ident:   {initial_hashes == p1_hashes} (Files unchanged on disk)')
assert p1.returncode == 1, 'Pass 1 exit code must be 1'
assert initial_hashes == p1_hashes, 'Pass 1 files must remain byte-for-byte identical'
assert 'service_auth.py' in p1.stdout and 'service_runner.py' in p1.stdout and 'service_storage.py' in p1.stdout

# Verify no merged diff lines exist in service_runner diff
assert not any(l.startswith('-') and 'cmd_list' in l for l in p1.stdout.splitlines()), "Malformed merged diff line detected in Pass 1!"
assert any(l.strip() == '+    cmd_list = ["ping", "-c", "1", host]' for l in p1.stdout.splitlines()), "cmd_list must be on its own clean '+' line!"
assert any(l.strip() == '-    subprocess.call(cmd, shell=True)' for l in p1.stdout.splitlines()), "subprocess.call must be on its own clean '-' line!"
print("    * Diff Format:  100% Clean (cmd_list starts on clean new line)")

# 3. EXECUTION PASS 2: ATOMIC DISK WRITE (--fix --write)
print('\n[3] Executing Pass 2: Atomic Disk Write (--fix --write)...')
p2, p2_time = run_cmd(['scratch/live_smoke_repo/', '--audit-all', '--fix', '--write'])
p2_hashes = hash_files()

print(f'    * Exit Code:    {p2.returncode} (Expected: 0)')
print(f'    * Duration:     {p2_time:.2f} ms ({p2_time/1000:.3f} s)')
print(f'    * Files Written:{all(initial_hashes[k] != p2_hashes[k] for k in initial_hashes)} (All 3 files safely patched)')
assert p2.returncode == 0, 'Pass 2 exit code must be 0'
assert all(initial_hashes[k] != p2_hashes[k] for k in initial_hashes), 'All 3 files must be patched'

# 4. RE-SCAN VERIFICATION
print('\n[4] Executing Final Authoritative Re-Scan (--audit-all)...')
p3, p3_time = run_cmd(['scratch/live_smoke_repo/', '--audit-all'])

print(f'    * Exit Code:    {p3.returncode} (Expected: 0)')
print(f'    * Duration:     {p3_time:.2f} ms ({p3_time/1000:.3f} s)')
print(f'    * Findings:     0 (ALL 3 VULNERABILITIES COMPLETELY RESOLVED)')
assert p3.returncode == 0, 'Re-scan exit code must be 0'
assert 'No security vulnerabilities detected.' in p3.stdout

print('\n======================================================================')
print('BENCHMARK SUMMARY REPORT')
print('======================================================================')
print(f'  Pass 1 (Preview Scan & Diff Generation): {p1_time:.2f} ms')
print(f'  Pass 2 (Remediation & Atomic Write):     {p2_time:.2f} ms')
print(f'  Re-scan (Post-remediation Verification): {p3_time:.2f} ms')
total_time = p1_time + p2_time + p3_time
print(f'  Total Pipeline Execution Time:           {total_time:.2f} ms ({total_time/1000:.3f} s)')
print('======================================================================')
print('ALL GATES AND INVARIANTS SATISFIED (100% SUCCESS)')
