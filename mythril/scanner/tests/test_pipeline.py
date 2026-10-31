import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import run_pipeline


class PipelineTests(unittest.TestCase):
    def test_audit_failure_keeps_source_and_creates_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chain = 'eth'
            address = '0x' + 'a' * 40
            source = root / 'contracts' / chain
            source.mkdir(parents=True)
            (source / 'Vault.sol').write_text('contract Vault {}')
            meta = {'address': address, 'source_files': {'Vault.sol': 'Vault.sol'}}
            metadata_path = run_pipeline.retention.metadata_path(root / 'metadata', chain, address)
            metadata_path.parent.mkdir(parents=True)
            metadata_path.write_text(json.dumps(meta))
            auditor = Mock(run_id='test')
            auditor.audit.return_value = Mock(status='failed', report=None, analysis_mode='source_creation')
            with patch.object(run_pipeline, 'ROOT', root):
                result = run_pipeline.audit_one(auditor, chain, address, meta, source)
            self.assertEqual(result, 'failed')
            self.assertTrue((source / 'Vault.sol').exists())
            self.assertIn('Scan incomplete', (root / 'reports' / chain / (address + '_test_status.txt')).read_text())


if __name__ == '__main__':
    unittest.main()

