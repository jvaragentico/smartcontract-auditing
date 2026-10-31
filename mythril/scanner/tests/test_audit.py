import json
import hashlib
import io
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, patch
import audit_contracts as audit


class AuditTests(unittest.TestCase):
    def test_saved_compiler_settings_reach_mythril(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            metadata['compiler_settings'] = {
                'viaIR': True, 'optimizer': {'enabled': True, 'runs': 200},
                'remappings': ['lib/core:solmate/=lib/solmate/', 'solady/=lib/solady/']}
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            def analyze(command, **kwargs):
                mount = next(arg for arg in command if 'dst=/workspace,readonly' in arg)
                stage = Path(mount.split('src=', 1)[1].split(',dst=')[0])
                settings_path = command[command.index('--solc-json') + 1]
                settings = json.loads((stage / Path(settings_path).name).read_text())
                self.assertTrue(settings['viaIR'])
                self.assertEqual(settings['optimizer']['runs'], 200)
                self.assertIn('lib/core:solmate/=lib/solmate/', settings['remappings'])
                self.assertIn('/workspace/lib/core:solmate/=lib/solmate/', settings['remappings'])
                return Mock(stdout=json.dumps({'success': True, 'issues': []}), stderr='', returncode=0)
            with patch('audit_contracts.subprocess.run', side_effect=analyze):
                self.assertEqual(runner.audit('eth', '0x'+'a'*40, metadata, output).status, 'clean')

    def test_partial_findings_are_saved_if_fallback_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            original = Mock(stdout=json.dumps({'success': True, 'issues': [{'title': 'partial finding'}]}),
                stderr='No contract was created during the execution of contract creation', returncode=1)
            with patch('audit_contracts.fetch_creation_input', return_value=None), \
                 patch('audit_contracts.fetch_deployed_runtime', side_effect=audit.AuditError('RPC unavailable')), \
                 patch('audit_contracts.subprocess.run', return_value=original):
                outcome = runner.audit('eth', '0x'+'a'*40, metadata, output)
            self.assertEqual(outcome.status, 'failed')
            report = json.loads(next((root/'findings'/'eth').glob('*_partial.json')).read_text())
            self.assertFalse(report['scan_complete'])
            self.assertEqual(report['issues'][0]['title'], 'partial finding')

    def test_runtime_findings_are_reported_with_reduced_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            original = Mock(stdout=json.dumps({'success': True, 'issues': []}),
                stderr='No contract was created during the execution of contract creation', returncode=0)
            retry = Mock(stdout=json.dumps({'success': True, 'issues': [{'title': 'runtime issue'}]}), stderr='', returncode=1)
            with patch('audit_contracts.fetch_creation_input', return_value=None), \
                 patch('audit_contracts.fetch_deployed_runtime', return_value=('0x6000', 123)), \
                 patch('audit_contracts.subprocess.run', side_effect=[original, retry]):
                outcome = runner.audit('eth', '0x'+'a'*40, metadata, output)
            self.assertEqual(outcome.status, 'findings')
            self.assertEqual(outcome.analysis_mode, 'deployed_runtime')
            self.assertEqual(outcome.runtime_block, 123)
            report = json.loads(outcome.report.read_text())
            self.assertIn('constructor', report['coverage_note'])

    def test_creation_fallback_uses_actual_deployment_input(self):
        address = '0x' + 'a'*40
        transaction = '0x' + 'b'*64
        client = Mock()
        client.get.return_value = {'status': 'ok', 'to': None,
            'created_contract': {'hash': address.upper().replace('0X','0x')}, 'raw_input': '0x6000'}
        with patch('scan_blockscout.Client', return_value=client):
            self.assertEqual(audit.fetch_creation_input('eth', address, {'deployment_transaction': transaction}), '0x6000')
            client.get.return_value['created_contract']['hash'] = '0x'+'c'*40
            self.assertIsNone(audit.fetch_creation_input('eth', address, {'deployment_transaction': transaction}))

    def test_constructor_failure_retries_with_deployment_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            original = Mock(stdout=json.dumps({'success': True, 'issues': []}),
                stderr='No contract was created during the execution of contract creation', returncode=0)
            retry = Mock(stdout=json.dumps({'success': True, 'issues': [{'title': 'issue'}]}), stderr='', returncode=1)
            with patch('audit_contracts.fetch_creation_input', return_value='0x6000'), \
                 patch('audit_contracts.subprocess.run', side_effect=[original, retry]) as command:
                outcome = runner.audit('eth', '0x'+'a'*40, metadata, output)
            self.assertEqual(outcome.status, 'findings')
            self.assertEqual(outcome.analysis_mode, 'deployment_bytecode')
            self.assertNotIn('--bin-runtime', command.call_args_list[1].args[0])
            self.assertEqual(json.loads(outcome.report.read_text())['analysis_mode'], 'deployment_bytecode')

    def test_runtime_without_findings_remains_incomplete_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            original = Mock(stdout=json.dumps({'success': True, 'issues': []}),
                stderr='No contract was created during the execution of contract creation', returncode=0)
            retry = Mock(stdout=json.dumps({'success': True, 'issues': []}), stderr='', returncode=0)
            with patch('audit_contracts.fetch_creation_input', return_value=None), \
                 patch('audit_contracts.fetch_deployed_runtime', return_value=('0x6000', 123)), \
                 patch('audit_contracts.subprocess.run', side_effect=[original, retry]) as command:
                outcome = runner.audit('eth', '0x'+'a'*40, metadata, output)
            self.assertEqual(outcome.status, 'failed')
            self.assertIn('--bin-runtime', command.call_args_list[1].args[0])
            self.assertEqual(len(list(output.glob('*.sol'))), 2)
            self.assertFalse((root/'findings'/'eth').exists())

    def test_cached_compiler_is_mounted_without_obsolete_solv_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            metadata['compiler_version'] = '0.8.17+commit.8df45f5f'
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            runner.compiler_options = Mock(return_value=('0.8.17',
                ['--mount', 'type=bind,src=compiler,dst=/usr/local/bin/solc,readonly']))
            result = Mock(stdout=json.dumps({'success': True, 'issues': []}), stderr='', returncode=0)
            with patch('audit_contracts.subprocess.run', return_value=result) as command:
                outcome = runner.audit('eth', '0x'+'a'*40, metadata, output)
            self.assertEqual(outcome.status, 'clean')
            args = command.call_args.args[0]
            self.assertNotIn('--solv', args)
            self.assertIn('type=bind,src=compiler,dst=/usr/local/bin/solc,readonly', args)

    def test_compiler_download_checks_official_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'solc-v0.8.17'
            artifact = b'test compiler binary'
            name = 'solc-linux-amd64-v0.8.17+commit.8df45f5f'
            manifest = {'releases': {'0.8.17': name}, 'builds': [{
                'path': name, 'version': '0.8.17', 'sha256': '0x'+hashlib.sha256(artifact).hexdigest()}]}
            with patch('audit_contracts.urlopen', side_effect=[io.BytesIO(json.dumps(manifest).encode()), io.BytesIO(artifact)]):
                audit.install_compiler('0.8.17', destination)
            self.assertEqual(destination.read_bytes(), artifact)

    def test_compiler_download_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)/'solc-v0.8.17'
            name = 'solc-linux-amd64-v0.8.17+commit.8df45f5f'
            manifest = {'releases': {'0.8.17': name}, 'builds': [{
                'path': name, 'version': '0.8.17', 'sha256': '0x'+'0'*64}]}
            with patch('audit_contracts.urlopen', side_effect=[io.BytesIO(json.dumps(manifest).encode()), io.BytesIO(b'wrong')]):
                with self.assertRaisesRegex(audit.AuditError, 'SHA-256'):
                    audit.install_compiler('0.8.17', destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_outer_timeout_is_a_failed_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            with patch('audit_contracts.subprocess.run', side_effect=[
                    subprocess.TimeoutExpired('docker', 1), Mock(returncode=0)]) as command:
                outcome = runner.audit('eth', '0x'+'e'*40, metadata, output)
            self.assertEqual(outcome.status, 'failed')
            self.assertEqual(runner.failures, 1)
            self.assertEqual(len(list(output.glob('*.sol'))), 2)
            self.assertEqual(command.call_count, 2)  # Timeout also removes the named container.

    def test_incomplete_analysis_is_failed_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            result = Mock(stdout=json.dumps({'success': True, 'issues': []}),
                          stderr='No contract was created during the execution of contract creation', returncode=0)
            with patch('audit_contracts.subprocess.run', return_value=result), \
                 patch('audit_contracts.fetch_creation_input', return_value=None), \
                 patch('audit_contracts.fetch_deployed_runtime', side_effect=audit.AuditError('RPC unavailable')):
                outcome = runner.audit('eth', '0x'+'d'*40, metadata, output)
            self.assertEqual(outcome.status, 'failed')
            self.assertEqual(runner.failures, 1)
            self.assertEqual(len(list(output.glob('*.sol'))), 2)

    def test_cached_exact_compiler_version_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = audit.Auditor(root/'sources', root/'findings', 'docker', 1)
            runner.compilers.mkdir()
            (runner.compilers/'solc-v0.8.24').write_bytes(b'test marker')
            with patch('audit_contracts.subprocess.run') as command:
                version, mounts = runner.compiler_options({'compiler_version': 'v0.8.24+commit.e11b9ed9'})
            self.assertEqual(version, '0.8.24')
            self.assertIn('/usr/local/bin/solc,readonly', mounts[1])
            command.assert_not_called()
            with self.assertRaises(audit.AuditError):
                runner.compiler_options({'compiler_version': 'unknown'})

    def prepare(self, root):
        output = root / 'sources'
        output.mkdir()
        (output / 'Main_address.sol').write_text('pragma solidity ^0.8.19; contract Main {}')
        (output / 'Dep_address.sol').write_text('pragma solidity ^0.8.19; library Dep {}')
        return output, {'entry_file': 'src/Main.sol', 'compiler_version': '0.8.19',
                        'source_files': {'src/Main.sol': 'Main_address.sol', 'lib/Dep.sol': 'Dep_address.sol'}}

    def test_clean_scan_writes_no_finding_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root / 'findings', 'docker', 1)
            result = Mock(stdout=json.dumps({'success': True, 'issues': []}), stderr='', returncode=0)
            with patch('audit_contracts.subprocess.run', return_value=result) as command:
                self.assertTrue(runner.audit('eth', '0x' + 'a'*40, metadata, output))
            self.assertFalse((root/'findings').exists())
            self.assertEqual(runner.scanned, 1)
            self.assertIn('--network', command.call_args.args[0])
            self.assertEqual(len(list(output.glob('*.sol'))), 2)

    def test_finding_writes_report_and_analyzer_error_is_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            runner = audit.Auditor(output, root/'findings', 'docker', 1)
            result = Mock(stdout=json.dumps({'success': True, 'issues': [{'title': 'Dependence on tx.origin'}]}), stderr='', returncode=1)
            with patch('audit_contracts.subprocess.run', return_value=result):
                self.assertTrue(runner.audit('base', '0x'+'b'*40, metadata, output))
            report = list((root/'findings'/'base').glob('*.json'))
            self.assertEqual(len(report), 1)
            self.assertEqual(json.loads(report[0].read_text())['issues'][0]['title'], 'Dependence on tx.origin')
            failed = Mock(stdout=json.dumps({'success': False, 'error': 'compiler unavailable'}), stderr='', returncode=1)
            with patch('audit_contracts.subprocess.run', return_value=failed):
                self.assertFalse(runner.audit('bnb', '0x'+'c'*40, metadata, output))
            self.assertEqual(runner.failures, 1)
            self.assertEqual(len(list((root/'findings').glob('audit_errors_*.jsonl'))), 1)
            self.assertFalse((root/'findings'/'bnb').exists())

    def test_refuses_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, metadata = self.prepare(root)
            metadata['source_files'] = {'../outside.sol': 'Main_address.sol'}
            metadata['entry_file'] = '../outside.sol'
            stage = root/'stage'
            stage.mkdir()
            with self.assertRaises(audit.AuditError):
                audit.stage_sources(metadata, output, stage)

if __name__ == '__main__':
    unittest.main()

