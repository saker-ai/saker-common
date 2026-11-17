import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load('wardn_release')
probe = load('wardn_probe')


class ReleaseEvidenceTest(unittest.TestCase):
    def receipts(self):
        manifest = {'components': {}}
        runtime = {'components': {}, 'acceptance': dict.fromkeys(release.REQUIRED, 'PASS'), 'cleanup': 'PASS'}
        for name in release.REPOSITORIES:
            manifest['components'][name] = {'commit': 'a' * 40, 'clean': True,
                        'sdk_version': 'v0.3.0' if name not in ('sdk', 'wardn') else None,
                        'local_replace': False, 'binary_sha256': 'b' * 64}
            runtime['components'][name] = {'commit': 'a' * 40, 'binary_sha256': 'b' * 64,
                'backup_sha256': 'c' * 64, 'rollback_sha256': 'd' * 64, 'schema_version': '5',
                'migration': 'PASS', 'health': 'PASS', 'data_preservation': 'PASS', 'consumer_import': 'PASS'}
        return manifest, runtime

    def test_matching_receipts(self):
        manifest, runtime = self.receipts()
        self.assertEqual(release.verify(manifest, runtime)['status'], 'PASS')

    def test_incomplete_or_mismatched_evidence_never_passes(self):
        for kind in ('dirty', 'sdk_drift', 'binary_drift', 'missing_backup', 'not_run', 'cleanup', 'source_drift'):
            with self.subTest(kind=kind):
                manifest, runtime = self.receipts()
                current = None
                if kind == 'dirty':
                    manifest['components']['chat']['clean'] = False
                elif kind == 'sdk_drift':
                    manifest['components']['chat']['sdk_version'] = 'v0.2.0'
                elif kind == 'binary_drift':
                    runtime['components']['chat']['binary_sha256'] = 'e' * 64
                elif kind == 'missing_backup':
                    del runtime['components']['corpus']['backup_sha256']
                elif kind == 'not_run':
                    runtime['acceptance']['global_logout'] = 'NOT_RUN'
                elif kind == 'cleanup':
                    runtime['cleanup'] = 'FAIL'
                else:
                    current = copy.deepcopy(manifest)
                    current['components']['chat']['commit'] = 'e' * 40
                self.assertEqual(release.verify(manifest, runtime, current)['status'], 'FAIL')


class ProbeBoundariesTest(unittest.TestCase):
    def test_unapproved_redirect_rejected_before_token_fragment(self):
        session = probe.Session({'wardn.example'})
        with patch.object(session, 'request', return_value=(302, {'Location': 'https://evil.example/#oidc_result=secret'}, b'', 'https://wardn.example')):
            with self.assertRaises(probe.ProbeError):
                session.follow('https://wardn.example')

    def test_no_plaintext_or_embedded_credentials(self):
        for url in ('http://wardn.example', 'https://name:secret@wardn.example', 'https://evil.example'):
            with self.subTest(url=url), self.assertRaises(probe.ProbeError):
                probe.Session({'wardn.example'}).request(url)

    def test_cleanup_cannot_target_existing_users(self):
        worker = probe.Probe({'issuer': 'https://wardn.example/identity', 'apps': {}})
        worker.user = {'name': 'existing-real-user'}
        with patch.object(worker, 'native') as native, self.assertRaises(probe.ProbeError):
            worker.cleanup()
        native.assert_not_called()

    def test_credentials_must_be_private(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'credentials.json'
            path.write_text('{}')
            path.chmod(0o644)
            with self.assertRaises(probe.ProbeError):
                probe.private_file(path)
            path.chmod(0o600)
            self.assertEqual(probe.private_file(path), path)


if __name__ == '__main__':
    unittest.main()
