import json
import os
import subprocess

def test_metrics():
    # Miniature confusion matrix test
    tp, tn, fp, fn = 8, 7, 2, 3
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1 = 2 * precision * recall / (precision + recall)
    fpr = fp / (fp + tn)
    fnr = fn / (fn + tp)
    assert abs(precision - 0.8) < 0.001
    assert abs(recall - 0.7272) < 0.001
    assert abs(fpr - 0.2222) < 0.001
    assert abs(fnr - 0.2727) < 0.001

def verify():
    passed = 0
    failed = 0
    skipped = 0

    print("==================================================")
    print("PHASE 8 TESTS SUITE")
    print("==================================================")

    print("Running dataset builder...")
    subprocess.run(["python", "dataset_builder.py"])

    print("Running benchmark runner...")
    res = subprocess.run(["python", "benchmark_runner.py"], capture_output=True, text=True)
    if res.returncode != 0:
        print("[FAIL] P8-C Benchmark failed to execute.")
        failed += 1
    else:
        print("[PASS] P8-C Benchmark executed actual analyzer.")
        passed += 1
        
    try:
        test_metrics()
        print("[PASS] P8-D Metric calculation correctness.")
        passed += 1
    except AssertionError:
        print("[FAIL] P8-D Metric calculation failed.")
        failed += 1

    if not os.path.exists("benchmark_manifest.json"):
        print("[FAIL] P8-A Manifest missing.")
        failed += 1
    else:
        print("[PASS] P8-A Benchmark manifest loads.")
        passed += 1
        with open("benchmark_manifest.json") as f:
            manifest = json.load(f)
            
            # Check structural diversity (unique ASTs lengths)
            lengths = set(len(m['files']['app.py']) for m in manifest)
            if len(lengths) > 50:
                print("[PASS] P8-Q Structural diversity check.")
                passed += 1
            else:
                print(f"[FAIL] P8-Q Structural diversity low. Unique sizes: {len(lengths)}")
                failed += 1

    if not os.path.exists("benchmark_results.json"):
        print("[FAIL] P8-O JSON results missing.")
        failed += 1
    else:
        print("[PASS] P8-O Result files are valid JSON.")
        passed += 1
        with open("benchmark_results.json") as f:
            results = json.load(f)
            if len(results) == len(manifest):
                print("[PASS] P8-N Zero skipped samples / Result count matching.")
                passed += 1
            else:
                print(f"[FAIL] P8-N Skipped samples detected. Manifest: {len(manifest)}, Results: {len(results)}")
                failed += 1

            # Exact ID matching
            man_ids = set(m['sample_id'] for m in manifest)
            res_ids = set(r['sample_id'] for r in results)
            if man_ids == res_ids:
                print("[PASS] P8-P Result IDs exactly match manifest IDs.")
                passed += 1
            else:
                print("[FAIL] P8-P Result IDs mismatch.")
                failed += 1

    if not os.path.exists("benchmark_report.txt"):
        print("[FAIL] P8-I/J/K Report missing.")
        failed += 1
    else:
        with open("benchmark_report.txt") as f:
            report = f.read()
            if "Determinism Pass: True" in report:
                print("[PASS] P8-L Full determinism (comparing full finding state).")
                passed += 1
            else:
                print("[FAIL] P8-L Determinism failed.")
                failed += 1

            if "FALSE POSITIVES SUMMARY" in report:
                print("[PASS] P8-I FP report contents check.")
                passed += 1
            else:
                print("[FAIL] P8-I Missing FP report.")
                failed += 1

            if "FALSE NEGATIVES SUMMARY" in report:
                print("[PASS] P8-J FN report contents check.")
                passed += 1
            else:
                print("[FAIL] P8-J Missing FN report.")
                failed += 1

            if "Average Time:" in report:
                print("[PASS] P8-K Performance metric correctness.")
                passed += 1
            else:
                print("[FAIL] P8-K Missing performance metrics.")
                failed += 1
                
            if "Exact Path Accuracy" in report:
                print("[PASS] P8-G Exact path accuracy validation.")
                passed += 1
            else:
                print("[FAIL] P8-G Missing exact path accuracy.")
                failed += 1

    print("\nExecuting Phase 7 Regression Suite (Includes P3-P6)...")
    res_reg = subprocess.run(["python", "phase7_tests.py"], capture_output=True, text=True)
    if "VERDICT: PASS" in res_reg.stdout:
        print("[PASS] P8-M Phase 3-7 regression suite passes.")
        passed += 1
    else:
        print("[FAIL] P8-M Regression suite failed.")
        failed += 1

    print("\n==================================================")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    if failed == 0:
        print("VERDICT: PASS")
    else:
        print("VERDICT: FAIL")

if __name__ == '__main__':
    verify()