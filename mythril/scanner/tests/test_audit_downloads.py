import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import audit_downloads as runner


class ResumeTests(unittest.TestCase):
    def test_retry_failed_reads_the_migrated_failed_folder(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            address = '0x'+'a'*40
            runner.retention.write_metadata(home/'metadata'/'eth'/('contract_'+address+'.json'),
                {'address':address, 'retention_status':'audit_failed'})
            auditor = Mock(scanned=1)
            auditor.audit.return_value = runner.audit.AuditOutcome('failed')
            with patch.object(runner, '__file__', str(home/'audit_downloads.py')), \
                 patch.object(runner.audit, 'preflight', return_value='docker'), \
                 patch.object(runner.audit, 'Auditor', return_value=auditor), \
                 patch.object(runner, 'discover_manual', return_value=0), \
                 patch.object(runner.retention, 'apply'):
                self.assertEqual(runner.main(['--chains','eth']), 0)
                auditor.audit.assert_not_called()
                self.assertEqual(runner.main(['--chains','eth','--retry-failed']), 2)
                self.assertEqual(auditor.audit.call_args.args[3], home/'failed'/'eth')

    def test_default_audit_visits_every_supported_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(runner, '__file__', str(Path(temp)/'audit_downloads.py')), \
                 patch.object(runner.audit, 'preflight', return_value='docker'), \
                 patch.object(runner, 'discover_manual', return_value=0) as discover:
                self.assertEqual(runner.main([]), 0)
                self.assertEqual([call.args[2] for call in discover.call_args_list], list(runner.CHAINS))

    def test_report_bundle_preserves_exact_sources_and_import_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = root / 'sources'
            sources.mkdir()
            content = b'pragma solidity ^0.8.19;\r\ncontract Example {}\r\n'
            (sources / 'saved.sol').write_bytes(content)
            metadata = {'source_files': {'contracts/Example.sol': 'saved.sol'}}
            report = root / 'report.json'
            name = runner.audit.bundle_report_sources(report, metadata, sources)
            with zipfile.ZipFile(root / name) as bundle:
                self.assertEqual(bundle.namelist(), ['contracts/Example.sol'])
                self.assertEqual(bundle.read('contracts/Example.sol'), content)
            from text_report import render
            self.assertIn(name, render({'source_archive': name}))
            metadata['source_files'] = {'../escape.sol': 'saved.sol'}
            with self.assertRaises(runner.audit.AuditError):
                runner.audit.bundle_report_sources(report, metadata, sources)

    def test_compiler_ranges_and_mixed_dependencies(self):
        cases = [(['=0.8.33', '^0.8.4', '^0.8.0'], '0.8.33'),
                 (['>=0.6.0 <0.8.0', '^0.7.6'], '0.7.6'),
                 (['^0.5.0 || ^0.6.0', '0.6.11'], '0.6.11'),
                 (['^0.8.0', '^0.8.24'], '0.8.24'),
                 (['<= 0.5.4', '^0.5.0'], '0.5.0'),
                 (['~0.8.20', '>=0.8.22'], '0.8.22')]
        for pragmas, expected in cases:
            with self.subTest(pragmas=pragmas):
                self.assertEqual(runner.select_compiler(pragmas), expected)
        for pragmas in ([], ['^0.5.0', '^0.8.0'], ['banana 0.8.19'], ['^0.8.0 ||']):
            with self.assertRaises(ValueError):
                runner.select_compiler(pragmas)

    def test_new_manual_contract_is_scanned_once_and_new_addition_is_found(self):
        with tempfile.TemporaryDirectory() as temp:
            previous = Path.cwd()
            try:
                os.chdir(temp)
                folder = Path('contracts/eth')
                folder.mkdir(parents=True)
                addresses = ['0x' + digit * 40 for digit in ('1', '2')]

                class Auditor:
                    scanned = 0

                    def audit(self, chain, address, meta, current):
                        self.scanned += 1
                        return runner.audit.AuditOutcome('clean')

                auditor = Auditor()
                with patch.object(runner, '__file__', str(Path(temp)/'audit_downloads.py')), patch.object(runner.audit, 'preflight', return_value='docker'), patch.object(
                    runner.audit, 'Auditor', return_value=auditor
                ):
                    for address in addresses:
                        (folder / (address + '_Test.sol')).write_text(
                            'pragma solidity ^0.8.19; contract Test {}'
                        )
                        self.assertEqual(runner.main(['--chains', 'eth']), 0)
                        record = json.loads(Path('metadata/eth/contract_' + address + '.json').read_text())
                        self.assertEqual(record['retention_status'], 'clean_discarded')
                    self.assertEqual(auditor.scanned, 2)
                    self.assertEqual(runner.main(['--chains', 'eth']), 0)
                    self.assertEqual(auditor.scanned, 2)
            finally:
                os.chdir(previous)

    def test_existing_history_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'sources/eth'
            source.mkdir(parents=True)
            address = '0x' + 'a' * 40
            (source / (address + '_Test.sol')).write_text('pragma solidity ^0.8.19;')
            record = root / 'state/eth' / ('contract_' + address + '.json')
            runner.retention.write_metadata(record, {'retention_status': 'findings'})
            before = record.read_bytes()
            self.assertEqual(runner.discover_manual(root / 'sources', root / 'state', 'eth'), 0)
            self.assertEqual(record.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()

