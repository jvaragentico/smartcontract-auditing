"""Automatic Mythril symbolic analysis of downloaded Solidity sources."""
import json
from text_report import write_text_report
import argparse
import hashlib
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

LOG = logging.getLogger(__name__)
IMAGE = 'mythril/myth@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff'
ADDRESS = re.compile(r'0x[0-9a-f]{40}\Z')
SOLC_BINARIES = 'https://binaries.soliditylang.org/linux-amd64/'


class AuditError(RuntimeError):
    pass


def bundle_report_sources(report, metadata, output):
    """Keep exact saved sources with a report using original import paths."""
    archive = report.with_name(report.stem + '_sources.zip')
    mapping = metadata.get('source_files')
    if not isinstance(mapping, dict) or not mapping:
        raise AuditError('Source path mapping is missing')
    entries = []
    used = set()
    for original, filename in mapping.items():
        name = str(safe_original_path(original))
        if name.casefold() in used:
            raise AuditError('Conflicting source paths')
        used.add(name.casefold())
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise AuditError('Unsafe saved source filename')
        source = output / filename
        if source.is_symlink() or not source.is_file() or source.resolve().parent != output.resolve():
            raise AuditError('Missing or unsafe saved source')
        entries.append((name, source.read_bytes()))
    temporary = archive.with_name('.pending-' + uuid4().hex)
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, content in entries:
                bundle.writestr(name, content)
        temporary.replace(archive)
    finally:
        if temporary.exists():
            temporary.unlink()
    return archive.name


@dataclass(frozen=True)
class AuditOutcome:
    status: str
    report: Path | None = None
    analysis_mode: str = 'source_creation'
    runtime_block: int | None = None

    def __bool__(self):
        return self.status != 'failed'


def preflight():
    docker = shutil.which('docker')
    if not docker:
        raise AuditError('Docker is not installed or is not on PATH')
    try:
        subprocess.run([docker, 'image', 'inspect', IMAGE], check=True, capture_output=True, timeout=60)
        subprocess.run([docker, 'version', '--format', '{{.Server.Version}}'], check=True, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise AuditError('Docker is unavailable or the local mythril/myth:latest image is missing') from exc
    return docker


def safe_original_path(name):
    if not isinstance(name, str) or '\\' in name or '\x00' in name or ':' in name:
        raise AuditError('Unsafe original source path')
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(p in ('', '.', '..') for p in path.parts):
        raise AuditError('Unsafe original source path')
    return path


def remap_imports(content, source_name, settings, source_names):
    """Apply verified compiler remappings to imports in temporary audit copies."""
    remappings = (settings or {}).get('remappings', []) if isinstance(settings, dict) else []
    if not isinstance(remappings, list):
        return content
    rules = []
    for rule in remappings:
        if not isinstance(rule, str) or '=' not in rule:
            continue
        left, target = rule.split('=', 1)
        context, prefix = left.split(':', 1) if ':' in left else ('', left)
        if prefix and target and source_name.startswith(context):
            rules.append((len(context), len(prefix), prefix, target))
    rules.sort(reverse=True)
    pattern = re.compile(r'(\bimport\s+(?:[^;\n]*?\s+from\s+)?["\'])([^"\']+)(["\'])')
    def replace(match):
        old = match.group(2)
        for _, _, prefix, target in rules:
            if old.startswith(prefix):
                new = target + old[len(prefix):]
                if new in source_names:
                    return match.group(1) + new + match.group(3)
                break
        return match.group(0)
    return pattern.sub(replace, content)


def stage_sources(metadata, output, staging):
    mapping = metadata.get('source_files')
    if not isinstance(mapping, dict) or not mapping:
        raise AuditError('Source path mapping is missing')
    used = set()
    for name, filename in mapping.items():
        original = safe_original_path(name)
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise AuditError('Unsafe saved source filename')
        saved = output / filename
        if saved.is_symlink() or not saved.is_file() or not saved.resolve().is_relative_to(output.resolve()):
            raise AuditError('Missing or unsafe saved source')
        target = staging.joinpath(*original.parts)
        key = str(target).casefold()
        if key in used:
            raise AuditError('Conflicting source paths')
        used.add(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = saved.read_bytes()
        try:
            source = raw.decode('utf-8')
        except UnicodeDecodeError:
            target.write_bytes(raw)
        else:
            target.write_bytes(raw)
    entry = metadata.get('entry_file') or next(iter(mapping))
    if entry not in mapping:
        raise AuditError('Contract entry file is unavailable')
    return str(safe_original_path(entry))


def install_compiler(version, destination):
    """Fetch an official Linux compiler on the host and verify its SHA-256."""
    if not re.fullmatch(r'0\.[4-8]\.\d{1,3}', version):
        raise AuditError('Unsupported Solidity compiler version')
    request_headers = {'User-Agent': 'ContractExtractor/1.0', 'Accept': 'application/json'}
    temporary = destination.with_name('.download-' + uuid4().hex)
    try:
        with urlopen(Request(SOLC_BINARIES + 'list.json', headers=request_headers), timeout=30) as response:
            raw = response.read(5_000_001)
        if len(raw) > 5_000_000:
            raise AuditError('Solidity compiler manifest exceeds the size limit')
        manifest = json.loads(raw)
        filename = manifest.get('releases', {}).get(version)
        if (not isinstance(filename, str) or '/' in filename or '\\' in filename
                or not filename.startswith('solc-linux-amd64-v' + version + '+commit.')):
            raise AuditError(f'Official compiler manifest has no supported release for {version}')
        build = next((item for item in manifest.get('builds', [])
                      if item.get('path') == filename and item.get('version') == version), None)
        checksum = str((build or {}).get('sha256', '')).removeprefix('0x').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise AuditError('Official compiler manifest has no valid SHA-256')
        digest = hashlib.sha256()
        downloaded = 0
        with urlopen(Request(SOLC_BINARIES + filename, headers={'User-Agent': 'ContractExtractor/1.0'}), timeout=60) as response:
            with temporary.open('xb') as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > 100_000_000:
                        raise AuditError('Solidity compiler binary exceeds the size limit')
                    digest.update(chunk)
                    handle.write(chunk)
        if digest.hexdigest() != checksum:
            raise AuditError('Solidity compiler SHA-256 does not match the official manifest')
        os.chmod(temporary, 0o755)
        temporary.replace(destination)
    except (OSError, ValueError, HTTPError, URLError, TypeError) as exc:
        raise AuditError(f'Could not download verified Solidity compiler {version}: {exc}') from exc
    finally:
        if temporary.exists():
            temporary.unlink()


def fetch_deployed_runtime(chain, address):
    """Read bytecode at a fixed block from an RPC checked against the chain ID."""
    from chain_sources import CONFIG, SourcifyClient
    if chain not in CONFIG or not ADDRESS.fullmatch(address):
        raise AuditError('Unsupported chain or invalid address for runtime fallback')
    try:
        client = SourcifyClient(chain, 'https://sourcify.dev/chain/' + str(CONFIG[chain][0]), .4)
        block = client.rpc('eth_blockNumber', [])
        if not isinstance(block, str) or not re.fullmatch(r'0x[0-9a-fA-F]+', block):
            raise AuditError('RPC returned an invalid block number')
        code = client.rpc('eth_getCode', [address, block])
        if (not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', code)
                or len(code) > 2_000_002):
            raise AuditError('No valid deployed runtime bytecode was returned')
        return code, int(block, 16)
    except AuditError:
        raise
    except (RuntimeError, OSError, ValueError, TypeError) as exc:
        raise AuditError('Could not fetch deployed runtime bytecode: ' + str(exc)) from exc


def fetch_creation_input(chain, address, metadata):
    """Fetch a direct deployment's actual constructor input, when verifiable."""
    from scan_blockscout import Client, APIError
    explorers = {'eth': 'https://eth.blockscout.com', 'base': 'https://base.blockscout.com',
                 'optimism': 'https://optimism.blockscout.com',
                 'robinhood': 'https://robinhoodchain.blockscout.com',
                 'polygon': 'https://polygon.blockscout.com', 'arbitrum': 'https://arbitrum.blockscout.com'}
    txhash = metadata.get('deployment_transaction')
    if chain not in explorers or not isinstance(txhash, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', txhash):
        return None
    try:
        tx = Client(explorers[chain], .4).get('/transactions/' + txhash)
    except APIError as exc:
        LOG.warning('Deployment transaction unavailable for %s: %s', address, exc)
        return None
    if not isinstance(tx, dict):
        LOG.warning('Invalid deployment transaction response for %s', address)
        return None
    created = tx.get('created_contract') or {}
    if not isinstance(created, dict):
        return None
    code = tx.get('raw_input')
    if (tx.get('status') != 'ok' or tx.get('to') is not None
            or str(created.get('hash') or '').lower() != address
            or not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})+', code)
            or len(code) > 2_000_002):
        LOG.warning('No verified direct-deployment input for %s; trying deployed runtime', address)
        return None
    return code


class Auditor:
    def __init__(self, output_root, findings_root, docker, timeout=90):
        self.output_root = output_root
        self.findings_root = findings_root
        self.docker = docker
        self.timeout = timeout
        self.failures = 0
        self.scanned = 0
        self.run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8]
        self.work = findings_root.parent / '.audit_work'
        self.compilers = findings_root.parent / '.audit_solc'

    def compiler_options(self, metadata):
        version_text = str(metadata.get('compiler_version') or '')
        match = re.search(r'(?<![0-9])0\.(?:[4-8])\.\d{1,3}(?![0-9])', version_text)
        if not match:
            raise AuditError('Verified Solidity compiler version is missing or unsupported')
        version = match.group()
        if version == '0.8.19':
            return version, []  # The image already has this version of solc.
        self.compilers.mkdir(parents=True, exist_ok=True)
        binary = self.compilers / ('solc-v' + version)
        if not binary.is_file():
            LOG.info('Downloading and verifying official Solidity compiler %s', version)
            install_compiler(version, binary)
        # Mythril's --solv calls an obsolete installer even for cached versions.
        # Bind the verified binary over the image's default compiler instead.
        return version, ['--mount', f'type=bind,src={binary.resolve()},dst=/usr/local/bin/solc,readonly']

    def audit(self, chain, address, metadata, output):
        if not ADDRESS.fullmatch(address):
            raise AuditError('Invalid contract address')
        self.work.mkdir(parents=True, exist_ok=True)
        container = 'contract-audit-' + uuid4().hex
        analysis_mode, runtime_block = 'source_creation', None
        partial_issues = []
        version = None
        try:
            with tempfile.TemporaryDirectory(prefix='contract-', dir=self.work) as temp:
                stage = Path(temp)
                entry = stage_sources(metadata, output, stage)
                settings = metadata.get('compiler_settings') or {}
                if not isinstance(settings, dict):
                    raise AuditError('Invalid saved compiler settings')
                settings = dict(settings)
                # Mythril supplies an absolute entry path; dependencies may retain
                # relative source names. Support both forms of contextual remappings.
                remappings = settings.get('remappings', [])
                if not isinstance(remappings, list) or not all(isinstance(r, str) for r in remappings):
                    raise AuditError('Invalid saved compiler remappings')
                absolute_contexts = []
                for remapping in remappings:
                    prefix = remapping.split('=', 1)[0]
                    if ':' in prefix:
                        context = prefix.split(':', 1)[0]
                        if context and not context.startswith('/'):
                            absolute_contexts.append('/workspace/' + remapping)
                if remappings:
                    settings['remappings'] = remappings + absolute_contexts
                settings_name = '.mythril-settings-' + uuid4().hex + '.json'
                (stage / settings_name).write_text(json.dumps(settings), encoding='utf-8')
                version, compiler_mount = self.compiler_options(metadata)
                command = [self.docker, 'run', '--rm', '--name', container, '--network', 'none',
                           '--memory', '1g', '--cpus', '1', '--pids-limit', '128',
                           '--mount', f'type=bind,src={stage.resolve()},dst=/workspace,readonly',
                           *compiler_mount,
                           '--workdir', '/workspace', '--entrypoint', '/usr/local/bin/myth',
                           IMAGE, '-v', '3', 'analyze', '/workspace/' + entry,
                           '--solc-json', '/workspace/' + settings_name,
                           # Mythril silently returns partial results when its own short timeout
                           # fires. Keep its limits above our external limit so the subprocess
                           # timeout is recorded as a failed scan instead of a clean scan.
                           '-o', 'json', '-t', '1', '--execution-timeout', '86400', '--create-timeout', '86400',
                           '--no-onchain-data']
                LOG.info('Auditing %s %s with Mythril', chain, address)
                try:
                    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                                            errors='replace', timeout=self.timeout + 100)
                except subprocess.TimeoutExpired as exc:
                    subprocess.run([self.docker, 'rm', '-f', container], capture_output=True, timeout=30)
                    raise AuditError('Analyzer timed out') from exc
                try:
                    payload = json.loads(result.stdout)
                except ValueError as exc:
                    raise AuditError('Analyzer did not return valid JSON: ' + result.stderr[-1000:]) from exc
                if payload.get('success') is not True or not isinstance(payload.get('issues'), list):
                    raise AuditError('Analysis or compilation failed: ' + str(payload.get('error') or result.stderr[-1000:]))
                if (result.returncode not in (0, 1) or (not payload['issues'] and result.returncode != 0)):
                    raise AuditError('Analyzer did not complete a successful contract analysis: ' + result.stderr[-1000:])
                if re.search(r'\b(?:timed out|timeout reached|execution timeout)\b', result.stderr, re.IGNORECASE):
                    raise AuditError('Analyzer reported an incomplete or timed-out scan')
                if 'No contract was created during the execution of contract creation' in result.stderr:
                    partial_issues = list(payload['issues'])
                    LOG.warning('Constructor simulation failed for %s; checking actual deployment input', address)
                    code = fetch_creation_input(chain, address, metadata)
                    if code:
                        analysis_mode = 'deployment_bytecode'
                    else:
                        LOG.warning('Direct deployment input unavailable; checking deployed runtime for %s', address)
                        code, runtime_block = fetch_deployed_runtime(chain, address)
                        analysis_mode = 'deployed_runtime'
                    bytecode_name = '.bytecode-' + uuid4().hex + '.hex'
                    (stage / bytecode_name).write_text(code, encoding='ascii')
                    container = 'contract-audit-' + uuid4().hex
                    runtime_command = [self.docker, 'run', '--rm', '--name', container, '--network', 'none',
                        '--memory', '1g', '--cpus', '1', '--pids-limit', '128',
                        '--mount', f'type=bind,src={stage.resolve()},dst=/workspace,readonly',
                        '--workdir', '/workspace', '--entrypoint', '/usr/local/bin/myth', IMAGE,
                        '-v', '3', 'analyze', '-f', '/workspace/' + bytecode_name,
                        *(['--bin-runtime', '--unconstrained-storage'] if analysis_mode == 'deployed_runtime' else []),
                        '-o', 'json',
                        '-t', '1', '--execution-timeout', '86400', '--create-timeout', '86400', '--no-onchain-data']
                    try:
                        runtime_result = subprocess.run(runtime_command, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=self.timeout + 100)
                    except subprocess.TimeoutExpired as exc:
                        subprocess.run([self.docker, 'rm', '-f', container], capture_output=True, timeout=30)
                        raise AuditError('Runtime-bytecode analysis timed out') from exc
                    try:
                        runtime_payload = json.loads(runtime_result.stdout)
                    except ValueError as exc:
                        raise AuditError('Runtime analysis returned invalid JSON: ' + runtime_result.stderr[-1000:]) from exc
                    if (runtime_payload.get('success') is not True or not isinstance(runtime_payload.get('issues'), list)
                            or runtime_result.returncode not in (0, 1)
                            or (not runtime_payload['issues'] and runtime_result.returncode != 0)
                            or 'No contract was created during the execution of contract creation' in runtime_result.stderr
                            or re.search(r'\b(?:timed out|timeout reached|execution timeout)\b', runtime_result.stderr, re.IGNORECASE)):
                        raise AuditError('Runtime-bytecode analysis failed: ' + str(runtime_payload.get('error') or runtime_result.stderr[-1000:]))
                    payload['issues'].extend(runtime_payload['issues'])
                    LOG.info('Bytecode analysis completed for %s (%s)', address, analysis_mode)
                    if analysis_mode == 'deployed_runtime' and not payload['issues']:
                        raise AuditError('Runtime scan found no issues, but constructor analysis was incomplete; preserving the contract')
                self.scanned += 1
                issues = payload['issues']
                if issues:
                    folder = self.findings_root / chain
                    folder.mkdir(parents=True, exist_ok=True)
                    report = folder / (address + '_' + self.run_id + '.json')
                    source_archive = bundle_report_sources(report, metadata, output)
                    report.write_text(json.dumps({'chain': chain, 'address': address,
                        'analyzer': 'Mythril 0.24.8 (Docker image)',
                        'verified_compiler_version': metadata.get('compiler_version'),
                        'analyzer_compiler': version,
                        'analysis_mode': analysis_mode,
                        'runtime_block': runtime_block,
                        'coverage_note': ('Runtime bytecode analyzed with symbolic storage; constructor and proxy implementations may not be covered.'
                                          if analysis_mode == 'deployed_runtime' else
                                          'Actual deployment bytecode analyzed; source locations may be unavailable.'
                                          if analysis_mode == 'deployment_bytecode' else 'Source-based creation and runtime analysis.'),
                        'source_files': metadata.get('source_files'), 'source_archive': source_archive, 'issues': issues,
                        'automated_findings_require_manual_review': True}, indent=2), encoding='utf-8')
                    write_text_report(report)
                    LOG.warning('Audit found %s issue(s): %s', len(issues), report.with_suffix('.txt'))
                else:
                    LOG.info('Audit complete for %s: no findings', address)
                return (AuditOutcome('findings', report, analysis_mode, runtime_block) if issues
                        else AuditOutcome('clean', None, analysis_mode, runtime_block))
        except (AuditError, OSError, ValueError, subprocess.SubprocessError) as exc:
            self.failures += 1
            LOG.error('Audit FAILED for %s %s: %s', chain, address, exc)
            self.findings_root.mkdir(parents=True, exist_ok=True)
            if partial_issues:
                try:
                    folder = self.findings_root / chain
                    folder.mkdir(parents=True, exist_ok=True)
                    partial = folder / (address + '_' + self.run_id + '_partial.json')
                    source_archive = bundle_report_sources(partial, metadata, output)
                    partial.write_text(json.dumps({'chain': chain, 'address': address,
                        'analyzer': 'Mythril 0.24.8 (Docker image)',
                        'verified_compiler_version': metadata.get('compiler_version'),
                        'analyzer_compiler': version, 'analysis_mode': 'source_partial',
                        'scan_complete': False, 'error': str(exc), 'issues': partial_issues,
                        'source_files': metadata.get('source_files'), 'source_archive': source_archive,
                        'automated_findings_require_manual_review': True}, indent=2), encoding='utf-8')
                    write_text_report(partial)
                    LOG.warning('Preserved partial findings from incomplete scan: %s', partial.with_suffix('.txt'))
                except (OSError, AuditError) as report_error:
                    LOG.error('Unable to save partial findings: %s', report_error)
            error_log = self.findings_root / ('audit_errors_' + self.run_id + '.jsonl')
            with error_log.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps({'chain': chain, 'address': address, 'error': str(exc)}) + '\n')
            return AuditOutcome('failed', None, analysis_mode, runtime_block)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Re-run a security scan on one downloaded contract')
    parser.add_argument('--chain', required=True, choices=('eth', 'base', 'bnb', 'optimism', 'robinhood', 'polygon', 'arbitrum', 'avalanche', 'hyperliquid'))
    parser.add_argument('--address', required=True)
    parser.add_argument('--output', type=Path, default=(Path(__file__).resolve().parent / 'contracts'))
    parser.add_argument('--metadata-root', type=Path, default=(Path(__file__).resolve().parent / 'metadata'))
    parser.add_argument('--audit-output', type=Path, default=(Path(__file__).resolve().parent / 'reports'))
    parser.add_argument('--failed', action='store_true', help='Retry a separately preserved failed audit')
    parser.add_argument('--failed-output', type=Path, default=(Path(__file__).resolve().parent / 'failed'))
    parser.add_argument('--audit-timeout', type=int, default=90)
    args = parser.parse_args(argv)
    address = args.address.lower()
    if not ADDRESS.fullmatch(address) or not 1 <= args.audit_timeout <= 86000:
        parser.error('Invalid address or timeout')
    try:
        metadata = json.loads((args.metadata_root / args.chain / ('contract_' + address + '.json')).read_text(encoding='utf-8'))
        auditor = Auditor(args.output, args.audit_output, preflight(), args.audit_timeout)
        current = (args.failed_output if args.failed else args.output) / args.chain
        outcome = auditor.audit(args.chain, address, metadata, current)
        if args.failed:
            import retention
            retention.apply(args.chain, address, metadata, current, args.output / args.chain,
                            args.failed_output / args.chain, args.metadata_root,
                            args.metadata_root / '.retention_staging' / args.chain,
                            outcome, args.audit_output)
        return 0 if outcome else 2
    except (AuditError, OSError, ValueError, RuntimeError) as exc:
        LOG.error('Cannot start audit: %s', exc)
        return 2


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    sys.exit(main())

