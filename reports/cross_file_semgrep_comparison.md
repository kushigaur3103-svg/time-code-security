# Head-to-Head: TCS vs Semgrep on the 20 Cross-File Ground-Truth Fixtures

- Fixtures: `benchmark/fixtures/cross_file/` (20 labelled cases, 13 expected findings)
- TCS: inter-procedural engine + sanitizer suppression (`benchmark.cross_runner`), 170 ms
- Semgrep: official rulesets `p/default`, `p/security-audit`, 1.178.0 (open-source engine), 9.6 s
- Semgrep is scored at CWE granularity anywhere inside the case directory (no file or line requirement) because its analysis is file-local and can only reach the leaf sink, while the labels sit at the caller entry point. The handicap is removed, not added.

| Case # | Case Name | Ground Truth | TCS Result | Semgrep Result | Analysis / Why Semgrep Diverges |
| --- | --- | --- | --- | --- | --- |
| 1 | `case_01_multihop_sqli` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_01_multihop_sqli/repo01.py:7` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found in the leaf module; the 3-hop caller chain that makes it tainted is invisible. |
| 2 | `case_02_kwargs_command` | Bad (CWE-78 x1) | TP (1/1 findings) | TP - `case_02_kwargs_command/shell02.py:5` (CWE-78, subprocess-shell-true) | Sink line found; the keyword-argument binding that routes request data into it is not tracked. |
| 3 | `case_03_oop_instance_sqli` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_03_oop_instance_sqli/gateway03.py:6` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found; instance-method resolution never needed, so parity by accident. |
| 4 | `case_04_aliased_import_sqli` | Bad (CWE-89 x1) | TP (1/1 findings) | FN - no report | Miss: repo04.py executes a bare parameter (`execute(statement)`), so the pattern rule that needs concatenated text does not fire, and `import exec_query as run_q` is unresolvable within one file. |
| 5 | `case_05_sanitizer_middle_layer` | Good (sanitised) | TN (suppressed) | FP - `case_05_sanitizer_middle_layer/views05.py:9` (CWE-78, dangerous-system-call) | Middle-layer `build_safe()` escapes the value, but the sanitizer contract lives in another file, so the caller's os.system is still reported. |
| 6 | `case_06_untainted_constant` | Good | TN | FP - `case_06_untainted_constant/repo06.py:6` (CWE-89, sqlalchemy-execute-raw-query) | The caller passes a string literal (`load_report("sales_summary_2026")`) and leaves the request value unused; a file-local rule only sees `+ kind` on a parameter. |
| 7 | `case_07_safe_name_collision` | Good | TN | FP - `case_07_safe_name_collision/danger07.py:6` (CWE-89, sqlalchemy-execute-raw-query) | Reports the star-imported `danger07.py` definition although the explicit import shadows it and nothing ever calls it. |
| 8 | `case_08_cross_file_inheritance_bad` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_08_cross_file_inheritance_bad/repo.py:8` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found in the inherited base repository; the subclass binding is not needed for the hit. |
| 9 | `case_09_abstract_interface_override_good` | Good | TN | FP - `case_09_abstract_interface_override_good/base.py:8` (CWE-89, sqlalchemy-execute-raw-query) | `SafeHandler` overrides the unsafe base with DB-API parameter binding; the dead base fallback is reported anyway. |
| 10 | `case_10_circular_import_bad` | Bad (CWE-78 x1) | TP (1/1 findings) | FN - no report | Miss: the request source is in mod_a.py while `os.system("ping -c 1 " + host)` takes a bare parameter in mod_b.py, and the two modules import each other. |
| 11 | `case_11_circular_import_benign_good` | Good | TN | FP - `case_11_circular_import_benign_good/mod_b.py:7` (CWE-78, subprocess-shell-true) | Sink receives a module constant while the request-derived value stays unused; the cycle hides which value actually flows. |
| 12 | `case_12_aliased_module_namespace_bad` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_12_aliased_module_namespace_bad/service.py:7` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found in service.py; the `import service as db_svc` alias only matters at the labelled caller site (controller.py:6), which TCS binds through and a file-local rule never has to. |
| 13 | `case_13_shadowed_sink_name_good` | Good | TN | FP - `case_13_shadowed_sink_name_good/controller.py:5` (CWE-89, sql-injection-using-db-cursor-execute) | Same blind spot TCS just closed: `local_lib.execute(payload)` is a name collision, not a cursor, yet the Django cursor-execute rule fires on the attribute name. |
| 14 | `case_14_deep_4hop_transitive_bad` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_14_deep_4hop_transitive_bad/repo.py:7` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found in the 4th module; the chain that lifts taint three hops is not followed. |
| 15 | `case_15_intermediate_return_taint_bad` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_15_intermediate_return_taint_bad/repo.py:7` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found; return-taint through `get_untrusted_id()` is invisible, the sink's own concatenation carries the report. |
| 16 | `case_16_intermediate_return_sanitized_good` | Good (sanitised) | TN (suppressed) | FP - `case_16_intermediate_return_sanitized_good/repo.py:7` (CWE-89, sqlalchemy-execute-raw-query) | `int()` conversion happens one layer in, so the escaped value still reaches the sink line; TCS suppresses it, Semgrep cannot. |
| 17 | `case_17_cross_file_decorator_sanitizer_good` | Good | TN | FP - `case_17_cross_file_decorator_sanitizer_good/repo.py:7` (CWE-89, sqlalchemy-execute-raw-query) | A `@validated` decorator cleans the argument before the sink; decorators in another file are outside a file-local pattern. |
| 18 | `case_18_cross_file_decorator_passthrough_bad` | Bad (CWE-78 x1) | TP (1/1 findings) | FN - no report | Miss: `os.system("ls " + cmd)` concatenates a bare parameter, and the request source is 4 lines below in a different function behind a passthrough decorator. |
| 19 | `case_19_multi_sink_fanout_bad` | Bad (CWE-78, CWE-89 x2) | TP (2/2 findings) | TP - `case_19_multi_sink_fanout_bad/db_mod.py:7` (CWE-89, sqlalchemy-execute-raw-query) | SQL half found in db_mod.py; the command half in os_mod.py needs the same fan-out reasoning, so one of the two sinks is lost. Partial: CWE-78@controller.py:8 not reported. |
| 20 | `case_20_mixed_positional_kwargs_bad` | Bad (CWE-89 x1) | TP (1/1 findings) | TP - `case_20_mixed_positional_kwargs_bad/db.py:7` (CWE-89, sqlalchemy-execute-raw-query) | Sink line found in the last module of the positional -> keyword -> positional chain; the chain itself is untraced. |

## Summary Metrics

| Engine | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TCS | 12 | 0 | 8 | 0 | 100.00% | 100.00% | 1.0000 |
| Semgrep (OSS) | 9 | 8 | 0 | 3 | 52.94% | 75.00% | 0.6207 |

### Finding-level coverage

- Expected findings across the 12 Bad cases: **13**
- TCS reported **13/13** at the exact labelled (CWE, file, line) - recall 100.00%
- Semgrep covered **9/13** expected CWEs under the generous rule - recall 69.23%
- Semgrep emitted 17 CWE-bearing findings in total; 9 correspond to a labelled leak.

## Reading

Semgrep's reports are real: it finds the vulnerable sink line inside the leaf module in most Bad cases. What it cannot do is decide *whether that sink is reachable with tainted data*, because the source lives in another file. That is why it credits 0 of the 8 Good cases - the safe fixtures are safe for inter-procedural reasons (sanitizer in the middle layer, overridden abstract method, shadowed import, untainted constant, decorator that cleans the argument), none of which a file-local pattern can see.
