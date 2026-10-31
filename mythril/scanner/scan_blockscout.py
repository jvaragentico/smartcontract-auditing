"""Key-free Blockscout downloader. Python 3.10+, standard library only."""
import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import logging
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

LOG = logging.getLogger(__name__)
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}\Z')


class APIError(RuntimeError):
    pass


class Client:
    def __init__(self, base, interval=1.0):
        self.base = base.rstrip('/')
        self.interval = interval
        self.last = 0.0

    def get(self, path, params=None):
        url = self.base + '/api/v2' + path
        if params:
            url += '?' + urlencode(params)
        if path.endswith('/tokens'):
            LOG.info('Requesting ERC20 balance page for %s', path.split('/')[-2])
        for attempt in range(5):
            time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            try:
                req = Request(url, headers={'User-Agent': 'ContractExtractor/1.0',
                                            'Accept': 'application/json'})
                with urlopen(req, timeout=35) as response:
                    return json.load(response)
            except HTTPError as exc:
                if exc.code not in (429, 500, 502, 503, 504):
                    raise APIError(f'HTTP {exc.code} for {path}') from None
            except (URLError, TimeoutError, OSError, ValueError):
                pass
            if attempt < 4:
                LOG.warning('Request failed for %s; retry %s/4', path, attempt + 1)
                time.sleep(min(30, 2 ** attempt))
        raise APIError(f'Retry limit for {path}')

    def pages(self, path, params=None, max_pages=100000):
        base = dict(params or {})
        current = base.copy()
        seen = set()
        for _ in range(max_pages):
            data = self.get(path, current)
            if not isinstance(data, dict) or not isinstance(data.get('items'), list):
                raise APIError('Invalid paginated response')
            yield data['items']
            cursor = data.get('next_page_params')
            if not cursor:
                return
            key = json.dumps(cursor, sort_keys=True)
            if key in seen:
                raise APIError('Repeated pagination cursor')
            seen.add(key)
            # Blockscout uses the literal string "null" for nullable keyset values.
            # urlencode(None) produces "None", which the API rejects with HTTP 422.
            current = {**base, **{key: 'null' if value is None else value
                                 for key, value in cursor.items()}}
        raise APIError(f'Page limit ({max_pages}) reached for {path}; scan incomplete')


def decimal(value):
    result = Decimal(str(value))
    if not result.is_finite() or result < 0:
        raise ValueError('Invalid nonnegative number')
    return result


def portfolio(client, address, info, min_usd=None, max_usd=None, max_token_pages=1000):
    """Approximate USD lower bound from indexed holdings; unknown prices excluded."""
    holdings, unknown = [], []
    total = Decimal(0)
    native = int(info['coin_balance'])
    if native < 0:
        raise ValueError('Negative balance')
    try:
        price = decimal(info['exchange_rate'])
        usd = Decimal(native) / Decimal(10 ** 18) * price
        holdings.append({'asset': 'native', 'raw_balance': str(native),
                         'price_usd': str(price), 'usd': str(usd)})
        total += usd
    except (KeyError, ValueError, InvalidOperation):
        unknown.append('native')
    LOG.info('%s: priced native balance approximately $%s', address, total)
    # A sufficient native balance proves eligibility without querying token pages.
    # This is a lower bound; metadata must not imply a full portfolio valuation.
    if max_usd is not None and total > max_usd:
        return total, holdings, unknown
    if max_usd is None and min_usd is not None and total >= min_usd:
        return total, holdings, unknown
    seen = set()
    LOG.info('%s: checking ERC20 holdings (up to %s pages)', address, max_token_pages)
    for page_number, rows in enumerate(client.pages('/addresses/' + address + '/tokens', {'type': 'ERC-20'}, max_pages=max_token_pages), 1):
        for row in rows:
            token = row.get('token') or {}
            asset = (token.get('address_hash') or '').lower()
            if not ADDRESS.fullmatch(asset) or asset in seen or token.get('type') != 'ERC-20':
                continue
            seen.add(asset)
            try:
                amount = int(row['value'])
                places = int(token['decimals'])
                if amount < 0 or not 0 <= places <= 255:
                    raise ValueError('Invalid token units')
                if not amount:
                    continue
                price = decimal(token['exchange_rate'])
                usd = Decimal(amount) / (Decimal(10) ** places) * price
                total += usd
                holdings.append({'asset': asset, 'raw_balance': str(amount),
                                 'decimals': places, 'price_usd': str(price), 'usd': str(usd)})
            except (KeyError, TypeError, ValueError, InvalidOperation):
                unknown.append(asset)
        LOG.info('%s: checked ERC20 page %s; priced total approximately $%s; %s unpriced tokens',
                 address, page_number, total, len(unknown))
        if max_usd is not None and total > max_usd:
            return total, holdings, unknown
        if max_usd is None and min_usd is not None and total >= min_usd:
            return total, holdings, unknown
    return total, holdings, unknown


def value_in_range(total, minimum, maximum=None):
    return total >= minimum and (maximum is None or total <= maximum)


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp lacks timezone')
    return parsed.timestamp()


def recent(value, now):
    return 0 <= now - timestamp(value) <= 86400


def safe(value):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', value)[:100] or 'Contract'


def save(run, address, source, metadata, metadata_dir=None):
    if source.get('is_verified') is not True or source.get('language', '').lower() != 'solidity':
        raise ValueError('Not verified Solidity')
    main_source = source.get('source_code')
    if not isinstance(main_source, str) or not main_source.strip():
        raise ValueError('Missing main source')
    files = [(source.get('file_path') or 'Contract.sol', main_source)]
    for extra in source.get('additional_sources') or []:
        path, content = extra.get('file_path', ''), extra.get('source_code')
        if path.lower().endswith('.sol') and isinstance(content, str) and content.strip():
            files.append((path, content))
    run.mkdir(parents=True, exist_ok=True)
    mapping = {}
    name = safe(source.get('name') or 'Contract')
    for index, (original, content) in enumerate(files):
        suffix = '' if len(files) == 1 else f'_{index}_{safe(original)}'
        filename = f'{name}_{address}{suffix}'
        if not filename.endswith('.sol'):
            filename += '.sol'
        write_checked(run / filename, content.encode('utf-8'))
        mapping[original] = filename
    metadata.update(name=name, compiler_version=source.get('compiler_version'),
                    entry_file=source.get('file_path') or 'Contract.sol',
                    optimization_enabled=source.get('optimization_enabled'),
                    optimization_runs=source.get('optimization_runs'),
                    compiler_settings=source.get('compiler_settings'),
                    is_fully_verified=source.get('is_fully_verified'),
                    is_partially_verified=source.get('is_partially_verified'), source_files=mapping)
    metadata_dir = metadata_dir or run
    metadata_dir.mkdir(parents=True, exist_ok=True)
    write_checked(metadata_dir / ('contract_' + address + '.json'),
                  json.dumps(metadata, indent=2).encode('utf-8'))
    return metadata


def write_checked(path, content):
    """Never overwrite different existing data; commit each file atomically."""
    if path.exists():
        if path.read_bytes() != content:
            raise APIError(f'File collision: {path.name}; existing file preserved')
        return
    temporary = path.with_name('.pending-' + uuid4().hex)
    try:
        temporary.write_bytes(content)
        # Windows rename refuses to replace an existing destination.
        temporary.rename(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def flatten_existing(output):
    """Migrate completed legacy downloads, with byte checks before removing originals."""
    if not output.exists():
        return 0
    root = output.resolve()
    moved = 0
    for metadata_path in list(output.glob('*/0x*/metadata.json')):
        if metadata_path.is_symlink() or not metadata_path.resolve().is_relative_to(root):
            raise APIError('Unsafe legacy metadata path')
        record = json.loads(metadata_path.read_text(encoding='utf-8'))
        address = str(record.get('address', '')).lower()
        files = record.get('source_files') or {}
        if not ADDRESS.fullmatch(address) or not files:
            raise APIError('Invalid legacy contract metadata')
        originals = []
        for name in set(files.values()):
            if not isinstance(name, str) or Path(name).name != name:
                raise APIError('Unsafe legacy source filename')
            original = metadata_path.parent / name
            if original.is_symlink() or not original.resolve().is_relative_to(root):
                raise APIError('Unsafe legacy source path')
            write_checked(output / name, original.read_bytes())
            originals.append(original)
        write_checked(output / ('contract_' + address + '.json'),
                      json.dumps(record, indent=2).encode('utf-8'))
        # Copies are complete and byte-verified; only named files inside output are removed.
        for original in originals:
            original.unlink()
        metadata_path.unlink()
        if not any(metadata_path.parent.iterdir()):
            metadata_path.parent.rmdir()
        moved += 1
    for old_run in list(output.glob('blockscout-*')):
        if not old_run.is_dir() or old_run.is_symlink():
            continue
        report = old_run / 'metadata.json'
        if report.is_file() and report.resolve().is_relative_to(root):
            write_checked(output / ('run_' + old_run.name + '.json'), report.read_bytes())
            report.unlink()
        if not any(old_run.iterdir()):
            old_run.rmdir()
    return moved



def previously_saved(output, explorer, metadata_dir=None, failed_dir=None):
    """Only completed per-contract downloads count, including those in partial runs."""
    addresses = set()
    for metadata_path in list((metadata_dir or output).glob('contract_0x*.json')) + list(output.glob('*/0x*/metadata.json')):
        try:
            record = json.loads(metadata_path.read_text(encoding='utf-8'))
            address = str(record.get('address', '')).lower()
            files = record.get('source_files') or {}
            disposition = record.get('retention_status')
            directory = failed_dir if disposition == 'audit_failed' and failed_dir else (output if metadata_dir else metadata_path.parent)
            complete = (disposition in ('clean_discarded', 'clean_cleanup_pending',
                                        'report_only', 'report_only_cleanup_pending') or
                        (files and all(isinstance(name, str) and Path(name).name == name and (directory / name).is_file()
                                       for name in files.values())))
            if (ADDRESS.fullmatch(address)
                    and str(record.get('explorer', '')).rstrip('/').lower() == explorer.rstrip('/').lower()
                    and complete):
                addresses.add(address)
        except (OSError, ValueError, TypeError):
            raise APIError('Cannot read saved-contract history; refusing to risk duplicates') from None
    return addresses


def load_rejected_cache(path, key, now):
    """Remember below-threshold valuations briefly; never cache API failures."""
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or data.get('key') != key or not isinstance(data.get('entries'), dict):
            return {}
        return {address: expiry for address, expiry in data['entries'].items()
                if ADDRESS.fullmatch(address) and isinstance(expiry, (float, int)) and now < expiry <= now + 86400}
    except (OSError, ValueError, TypeError):
        return {}


def save_rejected_cache(path, key, entries):
    temp = path.with_name('.candidate-cache-' + uuid4().hex)
    try:
        temp.write_text(json.dumps({'key': key, 'entries': entries}), encoding='utf-8')
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def candidates(client, funded, max_pages, started):
    """Funded discovery ranks by native balance and imposes no deployment-age limit."""
    path = '/addresses' if funded else '/transactions'
    params = {} if funded else {'filter': 'validated'}
    for page, rows in enumerate(client.pages(path, params, max_pages), 1):
        LOG.info('Checking discovery page %s (%s)', page, path)
        for row in rows:
            if funded:
                if row.get('is_contract') is True and row.get('is_verified') is True:
                    yield row.get('hash', ''), {}
            else:
                if timestamp(row['timestamp']) < started - 86400:
                    return
                if row.get('status') == 'ok' and recent(row['timestamp'], time.time()):
                    yield (row.get('created_contract') or {}).get('hash', ''), row


def resumed_candidates(client, max_pages, checkpoint_path, key):
    """Resume a funded feed at a page and skip rows already handled on that page."""
    cursor, processed = {}, set()
    try:
        state = json.loads(checkpoint_path.read_text(encoding='utf-8'))
        progress = state.get('entries', {})
        if state.get('key') == key and isinstance(progress, dict) and isinstance(progress.get('cursor'), dict) and isinstance(progress.get('processed'), list):
            cursor = progress['cursor']
            processed = {x for x in progress['processed'] if isinstance(x, str) and ADDRESS.fullmatch(x)}
            if progress.get('fallback') == 'sourcify' and hasattr(client, 'fallback') and hasattr(client, 'chain'):
                from chain_sources import SourcifyClient
                client.fallback = SourcifyClient(client.chain, client.base, client.interval)
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    if cursor or processed:
        LOG.info('Resuming discovery from saved page (%s candidates already handled on page)', len(processed))
    def checkpoint(next_cursor, done):
        backend = 'sourcify' if getattr(client, 'fallback', None) is not None else None
        save_rejected_cache(checkpoint_path, key, {'cursor': next_cursor, 'processed': sorted(done), 'fallback': backend})
    seen_cursors = set()
    for page in range(1, max_pages + 1):
        data = client.get('/addresses', cursor)
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            raise APIError('Invalid paginated response')
        LOG.info('Checking discovery page %s in this run (/addresses)', page)
        for row in data['items']:
            if not isinstance(row, dict) or row.get('is_contract') is not True or row.get('is_verified') is not True:
                continue
            address = str(row.get('hash', '')).lower()
            if not ADDRESS.fullmatch(address) or address in processed:
                continue
            yield address, {}
            processed.add(address)
            checkpoint(cursor, processed)
        next_cursor = data.get('next_page_params')
        if not next_cursor:
            checkpoint({}, set())
            LOG.info('Reached end of discovery; next run will refresh from the beginning')
            return
        if not isinstance(next_cursor, dict):
            raise APIError('Invalid pagination cursor')
        next_cursor = {k: 'null' if v is None else v for k, v in next_cursor.items()}
        marker = json.dumps(next_cursor, sort_keys=True)
        if marker in seen_cursors:
            raise APIError('Repeated pagination cursor')
        seen_cursors.add(marker)
        cursor, processed = next_cursor, set()
        checkpoint(cursor, set())
    raise APIError(f'Page limit ({max_pages}) reached for /addresses; scan incomplete')


def main(argv=None, client=None, on_saved=None, source_filter=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--explorer', default='https://eth.blockscout.com')
    parser.add_argument('--target', type=int, default=100)
    parser.add_argument('--min-usd', type=Decimal, default=Decimal('1000'))
    parser.add_argument('--max-usd', type=Decimal,
                        help='Inclusive maximum priced USD holdings; checks all indexed ERC20 pages')
    parser.add_argument('--funded', action='store_true',
                        help='Discover verified contracts by native balance, with no age limit')
    parser.add_argument('--max-pages', type=int, default=100000)
    parser.add_argument('--max-token-pages', type=int, default=1000,
                        help='Maximum ERC20 pages per candidate; incomplete portfolios are skipped')
    parser.add_argument('--interval', type=float, default=1.0)
    parser.add_argument('--output', type=Path, default=Path('downloaded_contracts'))
    parser.add_argument('--metadata-dir', type=Path, help='Store JSON outside the Solidity output folder')
    parser.add_argument('--failed-dir', type=Path, help='Location of separately preserved failed scans')
    parser.add_argument('--smoke-test', action='store_true', help='Test public feed access without downloading')
    args = parser.parse_args(argv)
    if (args.target < 1 or args.max_pages < 1 or args.max_token_pages < 1 or args.interval < 0.25
            or not args.min_usd.is_finite() or args.min_usd < 0):
        parser.error('Invalid target, page limit, interval or USD threshold')
    if args.max_usd is not None and (not args.max_usd.is_finite() or args.max_usd < args.min_usd):
        parser.error('--max-usd must be finite and greater than or equal to --min-usd')
    if urlparse(args.explorer).scheme != 'https' or not urlparse(args.explorer).netloc:
        parser.error('--explorer requires an HTTPS explorer URL')
    client = client or Client(args.explorer, args.interval)
    if args.smoke_test:
        data = client.get('/transactions', {'filter': 'validated'})
        if not isinstance(data.get('items'), list) or not data['items']:
            raise APIError('Transaction feed empty or invalid')
        print('PASS: public transaction feed reachable without an API key')
        return 0
    moved = flatten_existing(args.output)
    if moved:
        LOG.info('Flattened %s previously downloaded contracts', moved)
    historical = previously_saved(args.output, client.base, args.metadata_dir, args.failed_dir)
    LOG.info('Skipping %s previously saved contracts', len(historical))
    run = args.output
    run.mkdir(parents=True, exist_ok=True)
    metadata_dir = args.metadata_dir or run
    metadata_dir.mkdir(parents=True, exist_ok=True)
    cache_path = metadata_dir / 'rejected_candidates.json'
    cache_key = {'explorer': client.base, 'funded': args.funded,
                 'min_usd': str(args.min_usd), 'max_usd': str(args.max_usd)}
    rejected = load_rejected_cache(cache_path, cache_key, time.time())
    LOG.info('Temporarily skipping %s recently checked low-value candidates', len(rejected))
    report_name = 'run_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8] + '.json'
    started = time.time()
    saved, seen, errors = [], set(historical), 0
    reason = 'feed_exhausted'
    try:
        stop = False
        source = resumed_candidates(client, args.max_pages, metadata_dir / 'discovery_cursor.json', cache_key) if args.funded else candidates(client, args.funded, args.max_pages, started)
        for candidate_address, tx in source:
                address = candidate_address.lower()
                if not ADDRESS.fullmatch(address) or address in seen or rejected.get(address, 0) > time.time():
                    continue
                seen.add(address)
                LOG.info('Checking contract %s (saved %s/%s)', address, len(saved), args.target)
                try:
                    info = client.get('/addresses/' + address)
                    if info.get('is_verified') is not True or info.get('is_contract') is not True:
                        continue
                    total, holdings, unknown = portfolio(client, address, info, args.min_usd,
                                                         args.max_usd, args.max_token_pages)
                    if not value_in_range(total, args.min_usd, args.max_usd):
                        LOG.info('%s: skipped; priced value approximately $%s is outside $%s–$%s',
                                 address, total, args.min_usd,
                                 args.max_usd if args.max_usd is not None else 'unlimited')
                        rejected[address] = time.time() + 86400
                        try:
                            save_rejected_cache(cache_path, cache_key, rejected)
                        except OSError as exc:
                            LOG.warning('Unable to save candidate cache: %s', exc)
                        continue
                    LOG.info('%s: value qualifies; fetching verified source', address)
                    source = client.get('/smart-contracts/' + address)
                    if source_filter is not None and not source_filter(source):
                        LOG.info('%s: skipped by application focus filter', address)
                        continue
                    if not args.funded and not recent(tx['timestamp'], time.time()):
                        continue
                    metadata = dict(address=address, explorer=client.base,
                                    deployment_timestamp=tx.get('timestamp'),
                                    deployment_transaction=tx.get('hash') or info.get('creation_transaction_hash'),
                                    deployment_block=tx.get('block_number'), total_usd=str(total),
                                    discovery_mode='funded_no_age_limit' if args.funded else 'recent_24h',
                                    valuation='approximate_indexed_prices_no_freshness_guarantee',
                                    valuation_scope=('all_indexed_priced_holdings' if args.max_usd is not None
                                                     else 'threshold_lower_bound_not_full_portfolio'),
                                    min_usd=str(args.min_usd),
                                    max_usd=str(args.max_usd) if args.max_usd is not None else None,
                                    holdings=holdings, unpriced_tokens=unknown,
                                    downloaded_at=datetime.now(timezone.utc).isoformat(),
                                    balance_block=info.get('block_number_balance_updated_at'))
                    metadata['valuation_coverage'] = info.get('valuation_coverage', 'indexed_native_and_erc20')
                    if on_saved is not None:
                        # Persist before starting the audit so interruption cannot make an
                        # unaudited contract look complete on the next run.
                        metadata['retention_status'] = 'audit_pending'
                    saved.append(save(run, address, source, metadata, args.metadata_dir))
                    LOG.info('Saved %s/%s %s (~$%s)', len(saved), args.target, address, total)
                    if on_saved is not None:
                        on_saved(address, metadata, run)
                    if len(saved) == args.target:
                        reason, stop = 'target_met', True
                        break
                except (APIError, KeyError, ValueError, TypeError, InvalidOperation) as exc:
                    errors += 1
                    LOG.warning('Skipped candidate %s: %s: %s', address, type(exc).__name__, exc)
    except KeyboardInterrupt:
        reason = 'interrupted'
        raise
    except (APIError, KeyError, ValueError, TypeError) as exc:
        reason = 'scan_error'
        errors += 1
        LOG.error('Scan stopped: %s', exc)
    finally:
        report = dict(target=args.target, saved_count=len(saved), complete=len(saved) == args.target,
                      stop_reason=reason, errors=errors, previously_saved_count=len(historical), contracts=saved)
        (metadata_dir / report_name).write_text(json.dumps(report, indent=2), encoding='utf-8')
        LOG.info('Saved %s/%s contracts in %s (%s)', len(saved), args.target, run, reason)
    return 0 if len(saved) == args.target else 2


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    try:
        sys.exit(main())
    except APIError as exc:
        LOG.error('%s', exc)
        sys.exit(2)

