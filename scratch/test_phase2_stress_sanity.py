from tcs_cli import execute_tcs_scan

def run_stress_sanity():
    # 1. DICT KEY ISOLATION (Field Sensitivity Test)
    code_dict = '''from flask import request
import subprocess
d = {}
d['tainted'] = request.args.get('x')
d['safe'] = 'echo clean'
subprocess.run(d['safe'], shell=True)'''
    res_dict = execute_tcs_scan({'td.py': code_dict})
    dict_findings = res_dict.get('findings', [])
    print('Dict Safe Findings Count (Must be 0):', len(dict_findings))
    for f in dict_findings:
        print('  Unexpected finding:', f.get('cwe'), f.get('line_number'), f.get('sink_symbol'))

    # 2. WALRUS OUT-OF-BLOCK SCOPE PERSISTENCE
    code_walrus = '''from flask import request
import subprocess
if (cmd := request.args.get('c')):
    pass
subprocess.run(cmd, shell=True)'''
    res_walrus = execute_tcs_scan({'tw.py': code_walrus})
    walrus_findings = res_walrus.get('findings', [])
    print('Walrus Scope Findings Count (Must be 1):', len(walrus_findings))
    for f in walrus_findings:
        print('  Walrus finding:', f.get('cwe'), f.get('confidence_label'), f.get('sink_symbol'))
        nodes = f.get('proof_graph', {}).get('nodes', [])
        if nodes:
            print('  Hop 1:', nodes[0].get('symbol'), 'Type:', nodes[0].get('node_type'))

if __name__ == '__main__':
    run_stress_sanity()
