"""Keep findings, discard clean scans, and preserve failed audits separately."""
import json
import logging
from pathlib import Path
from uuid import uuid4
from types import SimpleNamespace
import scan_blockscout as core

LOG = logging.getLogger(__name__)


class RetentionError(RuntimeError):
    pass


def metadata_path(state, chain, address):
    return state / chain / ('contract_' + address + '.json')


def write_metadata(path, data):
    if path.is_symlink():
        raise RetentionError('Metadata path is a symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name('.pending-' + uuid4().hex)
    try:
        temp.write_text(json.dumps(data, indent=2), encoding='utf-8')
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()


def checked_sources(address, metadata, folder, allow_missing=False):
    if not core.ADDRESS.fullmatch(address) or metadata.get('address', '').lower() != address:
        raise RetentionError('Invalid contract address in metadata')
    files = metadata.get('source_files')
    if not isinstance(files, dict) or not files:
        raise RetentionError('Missing source mapping')
    root = folder.resolve()
    result = []
    for name in sorted(set(files.values())):
        if (not isinstance(name, str) or Path(name).name != name
                or address.lower() not in name.lower() or not name.lower().endswith('.sol')):
            raise RetentionError('Unsafe or unrelated source filename')
        path = folder / name
        if path.is_symlink() or path.resolve().parent != root:
            raise RetentionError('Unsafe source path')
        if not allow_missing and not path.is_file():
            raise RetentionError('Contract source is missing')
        result.append(path)
    return result


def copy_verified(source, destination):
    if source.is_symlink() or not source.is_file() or destination.is_symlink():
        raise RetentionError('Unsafe or missing source during retention')
    data = source.read_bytes()
    core.write_checked(destination, data)
    if destination.read_bytes() != data:
        raise RetentionError('Source copy verification failed')


def cleanup_clean(address, record, current, staging, meta, final_status='clean_discarded'):
    originals = checked_sources(address, record, current, allow_missing=True)
    backup = staging / address
    if backup.is_symlink() or not backup.is_dir():
        raise RetentionError('Clean-scan safety copies are unavailable')
    # Compare every remaining original against its safety copy before deleting anything.
    for source in originals:
        saved = backup / source.name
        if saved.is_symlink() or not saved.is_file():
            raise RetentionError('Clean-scan safety copy is missing')
        if source.exists() and source.read_bytes() != saved.read_bytes():
            raise RetentionError('Contract source changed during retention')
    for source in originals:
        if source.exists():
            source.unlink()
    record['retention_status'] = final_status
    write_metadata(meta, record)
    for source in originals:
        (backup / source.name).unlink()
    backup.rmdir()


def delete_reported(chain, address, primary, state, staging, findings):
    """Remove a completed finding's source while preserving its report and history."""
    meta = metadata_path(state, chain, address)
    if meta.is_symlink() or not meta.is_file():
        raise RetentionError('Contract metadata is missing or unsafe')
    record = json.loads(meta.read_text(encoding='utf-8'))
    if record.get('retention_status') != 'findings':
        raise RetentionError('Contract is not a completed findings scan')
    report = Path(record.get('findings_report') or '')
    if (report.is_symlink() or not report.is_file()
            or not report.resolve().is_relative_to((findings / chain).resolve())):
        raise RetentionError('Findings report is missing or outside its expected folder')
    payload = json.loads(report.read_text(encoding='utf-8'))
    if payload.get('address') != address or not isinstance(payload.get('issues'), list) or not payload['issues']:
        raise RetentionError('Findings report does not match the contract')
    originals = checked_sources(address, record, primary)
    backup = staging / address
    if backup.exists():
        raise RetentionError('Pending safety copies already exist')
    backup.mkdir(parents=True)
    for source in originals:
        copy_verified(source, backup / source.name)
    record['retention_status'] = 'report_only_cleanup_pending'
    record['cleanup_source_kind'] = 'primary'
    write_metadata(meta, record)
    cleanup_clean(address, record, primary, staging, meta, final_status='report_only')
    return len(originals)


def apply(chain, address, metadata, current, primary, failed, state, staging, outcome, findings):
    meta = metadata_path(state, chain, address)
    if not meta.is_file():
        raise RetentionError('Contract metadata is missing')
    record = json.loads(meta.read_text(encoding='utf-8'))
    originals = checked_sources(address, record, current)
    record['audit_analysis_mode'] = getattr(outcome, 'analysis_mode', 'unknown')
    record['audit_runtime_block'] = getattr(outcome, 'runtime_block', None)
    if outcome.status == 'findings':
        report = outcome.report
        if (report is None or report.is_symlink() or not report.is_file()
                or not report.resolve().is_relative_to((findings / chain).resolve())):
            raise RetentionError('A valid findings report is required to retain a contract')
        payload = json.loads(report.read_text(encoding='utf-8'))
        if not payload.get('issues') or payload.get('address') != address:
            raise RetentionError('Findings report does not match the contract')
        if current.resolve() != primary.resolve():
            primary.mkdir(parents=True, exist_ok=True)
            for source in originals:
                copy_verified(source, primary / source.name)
        record['retention_status'] = 'findings'
        record['findings_report'] = str(report)
        write_metadata(meta, record)
        if current.resolve() != primary.resolve():
            for source in originals:
                source.unlink()
        metadata.update(record)
        LOG.info('Keeping %s %s with findings', chain, address)
    elif outcome.status == 'failed':
        failed.mkdir(parents=True, exist_ok=True)
        if current.resolve() != failed.resolve():
            for source in originals:
                copy_verified(source, failed / source.name)
        record['retention_status'] = 'audit_failed'
        record['failed_source_dir'] = str(failed.resolve())
        write_metadata(meta, record)
        if current.resolve() != failed.resolve():
            for source in originals:
                source.unlink()
        metadata.update(record)
        LOG.warning('Preserved failed scan separately: %s', failed)
    elif outcome.status == 'clean':
        backup = staging / address
        if backup.exists():
            raise RetentionError('Pending clean-scan safety copies already exist')
        backup.mkdir(parents=True)
        for source in originals:
            copy_verified(source, backup / source.name)
        record['retention_status'] = 'clean_cleanup_pending'
        record['cleanup_source_kind'] = 'primary' if current.resolve() == primary.resolve() else 'failed'
        write_metadata(meta, record)
        cleanup_clean(address, record, current, staging, meta)
        metadata.update(record)
        LOG.info('Removed %s %s: scan completed with no findings', chain, address)
    else:
        raise RetentionError('Unknown audit outcome; sources preserved')


def recover_pending(state, chain, primary, failed, staging):
    """Preserve interrupted audits and finish safe, interrupted file moves."""
    folder = state / chain
    if not folder.exists():
        return
    for meta in folder.glob('contract_0x*.json'):
        record = json.loads(meta.read_text(encoding='utf-8'))
        address = str(record.get('address', '')).lower()
        status = record.get('retention_status')
        if status in ('clean_cleanup_pending', 'report_only_cleanup_pending'):
            kind = record.get('cleanup_source_kind')
            if kind not in ('primary', 'failed'):
                raise RetentionError('Pending cleanup has an unexpected source location')
            current = primary if kind == 'primary' else failed
            final_status = 'report_only' if status == 'report_only_cleanup_pending' else 'clean_discarded'
            cleanup_clean(address, record, current, staging, meta, final_status=final_status)
            LOG.info('Finished interrupted cleanup for %s %s', chain, address)
        elif status == 'audit_pending':
            record['audit_error'] = 'Interrupted before security audit completed'
            write_metadata(meta, record)
            apply(chain, address, record, primary, primary, failed, state, staging,
                  SimpleNamespace(status='failed', report=None), Path('.'))
            LOG.warning('Preserved interrupted audit separately: %s %s', chain, address)
        elif status == 'audit_failed' and primary.is_dir() and failed.is_dir():
            # If interrupted after verified copies and metadata were saved, finish
            # removing only exact matching originals; do not touch modified files.
            originals = checked_sources(address, record, primary, allow_missing=True)
            backups = checked_sources(address, record, failed)
            for original, backup in zip(originals, backups):
                if original.exists() and original.read_bytes() != backup.read_bytes():
                    raise RetentionError('Failed-scan copy differs from original')
            for original in originals:
                if original.exists():
                    original.unlink()

