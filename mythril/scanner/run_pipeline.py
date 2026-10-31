"""Download verified contracts and run Mythril after every completed download."""
import argparse
import json
import logging
from pathlib import Path
from decimal import Decimal

import audit_contracts as audit
import retention
import scan_blockscout as core
from chain_sources import AutoClient, SourcifyClient
from scan_chains import CHAINS

ROOT = Path(__file__).resolve().parent


def audit_one(auditor, chain, address, metadata, source_dir):
    result = auditor.audit(chain, address, metadata, source_dir)
    metadata['retention_status'] = {'findings': 'findings', 'clean': 'clean_preserved', 'failed': 'audit_failed'}[result.status]
    metadata['audit_analysis_mode'] = result.analysis_mode
    metadata['findings_report'] = str(result.report) if result.report else None
    retention.write_metadata(retention.metadata_path(ROOT / 'metadata', chain, address), metadata)
    if result.status != 'findings':
        folder = ROOT / 'reports' / chain
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (address + '_' + auditor.run_id + '_status.txt')).write_text(
            'Mythril 0.24.8\nContract: ' + address + '\nChain: ' + chain + '\nStatus: ' + result.status +
            ('\nNo findings reported; this is not proof of security.' if result.status == 'clean' else
             '\nScan incomplete. See audit_errors JSONL and any partial report.') + '\n', encoding='utf-8')
    return result.status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chains', nargs='+', choices=('eth', 'optimism', 'avalanche'), default=['eth', 'optimism', 'avalanche'])
    parser.add_argument('--target', type=int, default=20, help='New projects per chain')
    parser.add_argument('--min-usd', type=Decimal, default=Decimal('10000'))
    parser.add_argument('--max-pages', type=int, default=1000)
    parser.add_argument('--audit-timeout', type=int, default=90)
    parser.add_argument('--interval', type=float, default=1.0)
    args = parser.parse_args(argv)
    if args.target < 1 or args.max_pages < 1 or args.interval < .25 or args.audit_timeout < 1 or not args.min_usd.is_finite() or args.min_usd < 0:
        parser.error('Invalid limits')
    auditor = audit.Auditor(ROOT / 'contracts', ROOT / 'reports', audit.preflight(), args.audit_timeout)
    failures = []
    for chain in dict.fromkeys(args.chains):
        _, url = CHAINS[chain]
        client = SourcifyClient(chain, url, args.interval) if chain == 'avalanche' else AutoClient(chain, url, args.interval)
        source_dir = ROOT / 'contracts' / chain
        metadata_dir = ROOT / 'metadata' / chain
        # Recover pending or failed work before requesting more projects.
        for path in sorted(metadata_dir.glob('contract_0x*.json')):
            metadata = json.loads(path.read_text(encoding='utf-8'))
            if metadata.get('retention_status') in ('audit_pending', 'audit_failed'):
                if audit_one(auditor, chain, metadata['address'], metadata, source_dir) == 'failed':
                    failures.append(metadata['address'])
        def on_saved(address, metadata, run):
            if audit_one(auditor, chain, address, metadata, run) == 'failed':
                failures.append(address)
        options = ['--funded', '--explorer', url, '--target', str(args.target), '--min-usd', str(args.min_usd),
                   '--max-pages', str(args.max_pages), '--interval', str(args.interval), '--output', str(source_dir),
                   '--metadata-dir', str(metadata_dir), '--failed-dir', str(ROOT / 'failed' / chain)]
        try:
            if core.main(options, client=client, on_saved=on_saved):
                failures.append(chain + ': download shortfall')
        except (core.APIError, OSError, ValueError) as exc:
            failures.append(chain + ': ' + str(exc))
            logging.error('%s failed: %s', chain, exc)
    if failures:
        logging.warning('Incomplete work: %s', ', '.join(failures))
    return 2 if failures else 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    raise SystemExit(main())

