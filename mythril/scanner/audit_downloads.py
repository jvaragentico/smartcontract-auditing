"""Manually audit downloaded contracts with Mythril."""
import argparse
import json
import logging
import re
from pathlib import Path
import sys
import audit_contracts as audit
import retention
from scan_chains import CHAINS

def select_compiler(pragmas):
    """Select a compiler satisfying every source, including dependency ranges."""
    if not pragmas:
        raise ValueError('No Solidity pragma found; supply compiler_version in metadata')
    expressions = []
    candidates = {(0, 8, 19), (0, 4, 26), (0, 5, 17), (0, 6, 12), (0, 7, 6)}
    token = re.compile(r'(>=|<=|>|<|=|\^|~)?\s*(\d+)\.(\d+)\.(\d+)')
    for pragma in pragmas:
        alternatives = []
        for branch in pragma.split('||'):
            terms = []
            position = 0
            for match in token.finditer(branch):
                if branch[position:match.start()].strip():
                    raise ValueError('Unsupported Solidity pragma: ' + pragma)
                op = match.group(1) or '='
                version = tuple(map(int, match.groups()[1:]))
                candidates.add(version)
                if op == '>':
                    candidates.add((*version[:2], version[2] + 1))
                terms.append((op, version))
                position = match.end()
            if not terms or branch[position:].strip():
                raise ValueError('Unsupported Solidity pragma: ' + pragma)
            alternatives.append(terms)
        expressions.append(alternatives)

    def satisfies(candidate, term):
        op, version = term
        if op == '^':
            major, minor, patch = version
            upper = (major + 1, 0, 0) if major else ((0, minor + 1, 0) if minor else (0, 0, patch + 1))
            return version <= candidate < upper
        if op == '~':
            return version <= candidate < (version[0], version[1] + 1, 0)
        return {'=': candidate == version, '>=': candidate >= version,
                '<=': candidate <= version, '>': candidate > version,
                '<': candidate < version}[op]

    compatible = [v for v in candidates if v[0] == 0 and 4 <= v[1] <= 8
                  and all(any(all(satisfies(v, term) for term in branch)
                              for branch in alternatives) for alternatives in expressions)]
    if not compatible:
        raise ValueError('Solidity pragmas have no compatible compiler; supply metadata for the correct source bundle')
    chosen = (0, 8, 19) if (0, 8, 19) in compatible else min(compatible)
    return '.'.join(map(str, chosen))

def discover_manual(output, state, chain):
    """Register address-named source bundles without overwriting audit history."""
    groups = {}
    errors = 0
    for source in sorted((output / chain).glob('*.sol')):
        match = re.search(r'0x[0-9a-fA-F]{40}(?![0-9a-fA-F])', source.name)
        if not match:
            logging.warning('Skipping %s: filename must contain a contract address', source)
            errors += 1
            continue
        groups.setdefault(match.group().lower(), []).append(source)
    for address, sources in groups.items():
        path = retention.metadata_path(state, chain, address)
        if path.exists():
            continue  # Existing records are the authority for completed/failed scans.
        try:
            mapping = {}
            pragmas = []
            entry = None
            for source in sources:
                if source.is_symlink():
                    raise ValueError('Symlinked source is unsafe')
                # Manually exported bundles commonly use <address>_<original>.sol.
                original = re.sub(r'^0x[0-9a-fA-F]{40}_', '', source.name)
                audit.safe_original_path(original)
                if original in mapping:
                    raise ValueError('Duplicate original source filename')
                mapping[original] = source.name
                content = source.read_text(encoding='utf-8-sig')
                content = re.sub(r'/\*.*?\*/|//[^\n]*', '', content, flags=re.S)
                pragmas.extend(re.findall(r'\bpragma\s+solidity\s+([^;]+);', content))
                if re.search(r'\bcontract\s+\w+', content):
                    entry = entry or original
            version = select_compiler(pragmas)
            record = dict(address=address, source_files=mapping,
                          entry_file=entry or next(iter(mapping)),
                          compiler_version=version, compiler_version_origin='manual_pragma',
                          retention_status='audit_pending', manually_added=True)
            retention.write_metadata(path, record)
            logging.info('Registered manually added contract: %s %s', chain, address)
        except (OSError, ValueError, audit.AuditError, retention.RetentionError) as exc:
            errors += 1
            logging.error('Could not register %s %s: %s', chain, address, exc)
    return errors

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--chains', nargs='+', choices=CHAINS, default=list(CHAINS))
    p.add_argument('--retry-failed', action='store_true')
    p.add_argument('--audit-timeout', type=int, default=90)
    args = p.parse_args(argv)
    if not 1 <= args.audit_timeout <= 86000: p.error('Invalid timeout')
    output, state, failed, findings = (Path(__file__).resolve().parent / name for name in ('contracts', 'metadata', 'failed', 'reports'))
    try:
        auditor = audit.Auditor(output, findings, audit.preflight(), args.audit_timeout)
    except audit.AuditError as exc:
        logging.error('Analyzer unavailable: %s', exc)
        return 2
    failures = 0
    for chain in dict.fromkeys(args.chains):
        failures += discover_manual(output, state, chain)
        for path in sorted((state / chain).glob('contract_0x*.json')):
            try:
                meta = json.loads(path.read_text(encoding='utf-8'))
                status = meta.get('retention_status')
                if status in ('findings', 'report_only', 'clean_discarded'): continue
                if status == 'audit_failed' and not args.retry_failed: continue
                if status in ('clean_cleanup_pending', 'report_only_cleanup_pending'):
                    retention.recover_pending(state, chain, output / chain, failed / chain, state / '.retention_staging' / chain)
                    continue
                addr = meta['address'].lower()
                current = (failed if status == 'audit_failed' else output) / chain
                meta['retention_status'] = 'audit_pending' if status != 'audit_failed' else 'audit_failed'
                retention.write_metadata(path, meta)
                result = auditor.audit(chain, addr, meta, current)
                retention.apply(chain, addr, meta, current, output / chain, failed / chain,
                                state, state / '.retention_staging' / chain, result, findings)
                if result.status == 'failed': failures += 1
            except (audit.AuditError, retention.RetentionError, OSError, ValueError, KeyError) as exc:
                failures += 1
                logging.error('Could not process %s: %s', path, exc)
    logging.info('Manual audit completed: %s analyzed; %s failed', auditor.scanned, failures)
    return 2 if failures else 0

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    sys.exit(main())

