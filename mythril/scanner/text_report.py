"""Render saved Mythril JSON findings as readable text."""
import argparse
import json
from pathlib import Path


def render(data):
    lines = []
    if data.get('source_archive'):
        lines += ['Contract sources: ' + str(data['source_archive']),
                  'Extract this ZIP beside the report to inspect the original Solidity files.', '']
    if data.get('scan_complete') is False:
        lines += ['WARNING: Incomplete scan; findings may be partial.', str(data.get('error', '')), '']
    if data.get('coverage_note') and data.get('analysis_mode') in ('deployment_bytecode', 'deployed_runtime'):
        lines += ['Analysis coverage: ' + str(data['coverage_note']), '']
    def label_address(address):
        labels = {'0xaffeaffeaffeaffeaffeaffeaffeaffeaffeaffe': '[CREATOR]',
                  '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef': '[ATTACKER]'}
        return labels.get(str(address).lower(), str(address))
    for issue in data.get('issues', []):
        if not isinstance(issue, dict):
            continue
        def val(*keys):
            return next((issue[k] for k in keys if issue.get(k) is not None), 'Not available')
        lines += [f"==== {val('title')} ====", f"SWC ID: {val('swc-id', 'swc_id')}",
                  f"Severity: {val('severity')}", f"Contract: {val('contract')}",
                  f"Function name: {val('function')}", f"PC address: {val('address')}",
                  f"Estimated Gas Usage: {val('min_gas_used')} - {val('max_gas_used')}"]
        description = issue.get('description', 'Not available')
        if isinstance(description, dict):
            description = '\n'.join(str(description[k]) for k in ('head', 'tail') if description.get(k))
        lines += [str(description), '--------------------']
        filename = issue.get('filename') or issue.get('file')
        lineno = issue.get('lineno') or issue.get('line')
        lines += ['In file: ' + (str(filename) + (':' + str(lineno) if lineno is not None else '') if filename else 'Not available'), '']
        code = issue.get('code') or issue.get('source_code')
        if code:
            lines += [str(code), '']
        lines += ['--------------------', 'Initial State:', '']
        seq = issue.get('tx_sequence') or {}
        if not isinstance(seq, dict):
            seq = {}
        state = seq.get('initialState') or seq.get('initial_state') or {}
        accounts = state.get('accounts', {}) if isinstance(state, dict) else {}
        if isinstance(accounts, dict) and accounts:
            for address, account in accounts.items():
                if not isinstance(account, dict):
                    continue
                lines.append(f"Account: {label_address(address)}, balance: {account.get('balance', 'Not available')}, nonce:{account.get('nonce', 'Not available')}, storage:{account.get('storage', 'Not available')}")
        else:
            lines.append('Not available')
        lines += ['', 'Transaction Sequence:', '']
        steps = seq.get('steps') or []
        if not steps:
            lines.append('Not available')
        for step in steps:
            if not isinstance(step, dict):
                continue
            caller = label_address(step.get('origin') or step.get('caller') or 'Not available')
            function = step.get('name') or step.get('function')
            decoded = step.get('resolved_input', step.get('decoded_data'))
            if isinstance(decoded, list):
                decoded = tuple(decoded)
            if function:
                txdata = step.get('input') or step.get('calldata') or ''
                text = f"Caller: {caller}, function: {function}, txdata: {txdata}"
                if decoded:
                    text += f", decoded_data: {decoded}"
            else:
                text = f"Caller: {caller}, calldata: {step.get('calldata', '')}, decoded_data: {decoded if decoded else ''}"
            lines.append(text + f", value: {step.get('value', 'Not available')}")
        lines += ['', '']
    return '\n'.join(lines)


def write_text_report(path):
    path = Path(path)
    data = json.loads(path.read_text(encoding='utf-8'))
    output = path.with_suffix('.txt')
    output.write_text(render(data), encoding='utf-8')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create text versions of existing JSON findings.')
    parser.add_argument('--findings', type=Path, default=Path('audit_findings'))
    args = parser.parse_args()
    count = 0
    for path in args.findings.glob('*/*.json'):
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict) and data.get('issues'):
            print(write_text_report(path))
            count += 1
    print(f'Created {count} text report(s).')

