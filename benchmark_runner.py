import json
import time
import re
import sys
from ast_scanner import TaintTracker

def normalize_path(path_str):
    if not path_str: return None
    p = re.sub(r'SRC-\d+', 'SRC', path_str)
    p = re.sub(r'SNK-\d+', 'SNK', p)
    return p

def run_benchmark_cycle():
    with open('benchmark_manifest.json') as f:
        manifest = json.load(f)

    results = []
    tp = tn = fp = fn = inconclusive = 0
    path_acc_count = 0
    src_snk_acc_count = 0
    fps_details = []
    fns_details = []

    t_start = time.time()

    for case in manifest:
        t0 = time.time()
        tracker = TaintTracker(files=case['files'])
        sources, sinks, edges = tracker.analyze()
        dt = time.time() - t0
        
        sink_edges = [e for e in edges if e.target_id.startswith('SNK')]
        best_edge = max(sink_edges, key=lambda e: e.confidence) if sink_edges else None
            
        actual_kind = best_edge.kind if best_edge else "NO DATA FLOW"
        actual_conf = best_edge.confidence if best_edge else None
        
        exp_kind = case['expected_kind']
        exp_conf = case['expected_confidence']
        
        status = "INCONCLUSIVE"
        if exp_kind in ["CONFIRMED_DATA_FLOW", "POTENTIAL_DATA_FLOW"]:
            if actual_kind == exp_kind and actual_conf == exp_conf:
                status = "TP"
                tp += 1
                
                # Check path exact match
                actual_path = normalize_path(best_edge.transform) if best_edge else None
                if actual_path == case.get('expected_path'):
                    path_acc_count += 1
                
                # Check source and sink identity
                src_node = next((s for s in sources if s.id == best_edge.source_id), None) if best_edge else None
                snk_node = next((s for s in sinks if s.id == best_edge.target_id), None) if best_edge else None
                
                act_src = src_node.symbol.split('(')[0] if src_node else None
                act_snk = snk_node.symbol if snk_node else None
                
                if act_src == case.get('expected_source') and act_snk == case.get('expected_sink'):
                    src_snk_acc_count += 1
                    
            else:
                status = "FN"
                fn += 1
                fns_details.append(f"{case['sample_id']} | Exp: {exp_kind} | Act: {actual_kind}")
        else:
            if actual_kind == "NO DATA FLOW":
                status = "TN"
                tn += 1
            else:
                status = "FP"
                fp += 1
                fps_details.append(f"{case['sample_id']} | Exp: NO DATA FLOW | Act: {actual_kind}")
                
        results.append({
            "sample_id": case['sample_id'],
            "status": status,
            "actual_kind": actual_kind,
            "actual_confidence": actual_conf,
            "actual_path": normalize_path(best_edge.transform) if best_edge else None,
            "time_ms": dt * 1000
        })

    t_end = time.time()
    
    return {
        "results": results,
        "metrics": {
            "total": len(manifest),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "inconclusive": inconclusive,
            "path_acc_count": path_acc_count,
            "src_snk_acc_count": src_snk_acc_count,
            "time_total": t_end - t_start,
            "times": sorted([r['time_ms'] for r in results]),
            "fps": fps_details,
            "fns": fns_details
        }
    }

print("Running Pass 1...")
run1 = run_benchmark_cycle()
print("Running Pass 2 (Determinism Check)...")
run2 = run_benchmark_cycle()

determinism_pass = True
for r1, r2 in zip(run1['results'], run2['results']):
    if (r1['status'] != r2['status'] or 
        r1['actual_kind'] != r2['actual_kind'] or 
        r1['actual_confidence'] != r2['actual_confidence'] or 
        r1['actual_path'] != r2['actual_path']):
        determinism_pass = False
        break

m = run1['metrics']
tp, tn, fp, fn = m['tp'], m['tn'], m['fp'], m['fn']
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

times = m['times']
avg_t = sum(times) / len(times) if times else 0
med_t = times[len(times)//2] if times else 0
max_t = times[-1] if times else 0

report = f"""==================================================
SECURITY ANALYZER BENCHMARK REPORT
==================================================
Total Samples: {m['total']}
True Positives (TP): {tp}
True Negatives (TN): {tn}
False Positives (FP): {fp}
False Negatives (FN): {fn}

Precision: {precision:.4f}
Recall:    {recall:.4f}
F1 Score:  {f1:.4f}
FPR:       {fpr:.4f}
FNR:       {fnr:.4f}

Determinism Pass: {determinism_pass}
Exact Path Accuracy (TP): {m['path_acc_count']}/{tp}
Source/Sink Identity Accuracy (TP): {m['src_snk_acc_count']}/{tp}

Performance:
Total Time:   {m['time_total']:.2f}s
Average Time: {avg_t:.2f}ms
Median Time:  {med_t:.2f}ms
Max Time:     {max_t:.2f}ms

==================================================
FALSE POSITIVES SUMMARY ({fp})
==================================================
{chr(10).join(m['fps']) if m['fps'] else 'None.'}

==================================================
FALSE NEGATIVES SUMMARY ({fn})
==================================================
{chr(10).join(m['fns']) if m['fns'] else 'None.'}

==================================================
OUT-OF-SCOPE LIMITATIONS
==================================================
- Advanced OOP dispatch (classes/methods)
- Field-sensitive collection tracking (dicts, arrays)
- Dynamic / computed imports
"""

with open('benchmark_results.json', 'w') as f:
    json.dump(run1['results'], f, indent=2)

with open('benchmark_report.txt', 'w') as f:
    f.write(report)