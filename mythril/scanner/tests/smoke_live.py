"""Run the actual pinned Mythril container against an intentionally unsafe contract."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_contracts as audit

root = Path(__file__).resolve().parents[1]
address = '0x' + 'a' * 40
fixture = Path(__file__).with_name('VulnerableVault.sol')
metadata = {'address': address, 'entry_file': 'VulnerableVault.sol',
            'source_files': {'VulnerableVault.sol': fixture.name},
            'compiler_version': '0.8.19', 'compiler_settings': {}}
auditor = audit.Auditor(fixture.parent, root / 'reports', audit.preflight(), 90)
result = auditor.audit('practice', address, metadata, fixture.parent)
if result.status != 'findings' or not result.report:
    raise SystemExit('FAIL: Mythril did not return findings: ' + result.status)
payload = json.loads(result.report.read_text(encoding='utf-8'))
if not any(str(item.get('swc-id')) == '105' for item in payload['issues']):
    raise SystemExit('FAIL: expected SWC-105 was not detected')
print('PASS: detected SWC-105. Report:', result.report.with_suffix('.txt'))

