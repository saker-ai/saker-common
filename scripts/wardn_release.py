#!/usr/bin/env python3
"""Inventory and verify exact source/SDK/runtime evidence without deploying or invoking hosted CI."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SDK = 'github.com/saker-ai/saker-common/wardn'
REPOSITORIES = {'sdk': ('saker-common', 'wardn'), 'wardn': ('wardn', '.'),
                'chat': ('saker-web', '.'), 'peek': ('peek', '.'),
                'lanner': ('lanner-cloud-go-fc', '.'), 'corpus': ('corpus', 'upstream/weknora')}
REQUIRED = ('sso', 'profile_refresh', 'disable_reenable', 'global_logout', 'old_token_replay', 'rollback')


class Rejected(Exception):
    pass


def git(path, *args):
    result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise Rejected('source_unavailable')
    return result.stdout.strip()


def inventory(root):
    result = {'schema': 'wardn-release/v1', 'status': 'INVENTORY', 'components': {}}
    for name, (repo, module) in REPOSITORIES.items():
        path = root / repo
        go_mod = (path / module / 'go.mod').read_text()
        dependency = re.search(r'(?m)^\s*' + re.escape(SDK) + r'\s+(v[^\s]+)', go_mod)
        result['components'][name] = {'commit': git(path, 'rev-parse', 'HEAD'),
            'clean': not bool(git(path, 'status', '--porcelain')),
            'sdk_version': dependency.group(1) if dependency else None,
            'local_replace': bool(re.search(r'(?m)^replace[\s\S]*?' + re.escape(SDK) + r'\s*=>\s*(?:\.|/)', go_mod))}
    return result


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify(expected, runtime, current=None):
    errors = []
    components = expected.get('components', {})
    if set(components) != set(REPOSITORIES):
        errors.append('incomplete_component_inventory')
    versions = {value.get('sdk_version') for name, value in components.items() if name in ('chat', 'peek', 'lanner', 'corpus')}
    if len(versions) != 1 or None in versions:
        errors.append('sdk_versions_differ')
    for name, spec in components.items():
        if not re.fullmatch(r'[0-9a-f]{40}', spec.get('commit', '')):
            errors.append(name + ':invalid_source_commit')
        if not spec.get('clean') or spec.get('local_replace'):
            errors.append(name + ':unclean_or_local_dependency')
        if current and any(current.get('components', {}).get(name, {}).get(key)!=spec.get(key) for key in ('commit','clean','sdk_version','local_replace')):
            errors.append(name + ':source_changed_since_receipt')
        actual = runtime.get('components', {}).get(name, {})
        if actual.get('commit') != spec.get('commit'):
            errors.append(name + ':running_source_mismatch')
        if name == 'sdk':
            if actual.get('consumer_import') != 'PASS':
                errors.append(name + ':independent_import_not_verified')
            continue
        if actual.get('binary_sha256')!=spec.get('binary_sha256') or not spec.get('binary_sha256'):
            errors.append(name+':binary_not_bound_to_build_receipt')
        for key in ('binary_sha256', 'backup_sha256', 'rollback_sha256'):
            if not re.fullmatch(r'[0-9a-f]{64}', actual.get(key, '')):
                errors.append(name + ':' + key + '_missing')
        if actual.get('schema_version') is None or actual.get('migration') not in ('PASS', 'UNCHANGED'):
            errors.append(name + ':migration_not_verified')
        if actual.get('health') != 'PASS' or actual.get('data_preservation') != 'PASS':
            errors.append(name + ':runtime_not_verified')
    for check in REQUIRED:
        if runtime.get('acceptance', {}).get(check) != 'PASS':
            errors.append(check + ':acceptance_not_verified')
    if runtime.get('cleanup') != 'PASS':
        errors.append('synthetic_account_cleanup_not_verified')
    return {'schema': 'wardn-release-verification/v1', 'status': 'FAIL' if errors else 'PASS', 'errors': errors}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def health(config):
    report = {'schema': 'wardn-health/v1', 'status': 'PASS', 'services': {}}
    for name, spec in config['services'].items():
        url = spec['url']
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise Rejected('invalid_probe_url')
        begin = time.monotonic()
        try:
            opener = urllib.request.build_opener(NoRedirect())
            response = opener.open(urllib.request.Request(url, headers={'User-Agent': 'WardnHealth/1'}), timeout=15)
            with response:
                status = response.code
                content = response.read(65537)
            passed = status == spec.get('status', 200) and len(content) <= 65536
            if 'body_contains' in spec:
                passed = passed and spec['body_contains'].encode() in content
        except urllib.error.HTTPError as error:
            status, passed = error.code, error.code == spec.get('status', 200)
        except (OSError, ValueError):
            status, passed = 0, False
        report['services'][name] = {'status': 'PASS' if passed else 'FAIL', 'http_status': status,
                                    'duration_ms': round((time.monotonic() - begin) * 1000)}
        if not passed:
            report['status'] = 'FAIL'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inventory', 'verify', 'health'))
    parser.add_argument('--root', type=Path, help='workspace containing the six independent repositories')
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'inventory':
            if args.root is None:
                raise Rejected('workspace_root_required')
            result = inventory(args.root)
        elif args.action == 'verify':
            if args.manifest is None or args.runtime is None:
                raise Rejected('manifest_and_runtime_required')
            result = verify(json.loads(args.manifest.read_text()), json.loads(args.runtime.read_text()),
                            inventory(args.root) if args.root else None)
        else:
            if args.config is None:
                raise Rejected('health_config_required')
            result = health(json.loads(args.config.read_text()))
    except (Rejected, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {'status': 'FAIL', 'error': str(error) if isinstance(error, Rejected) else type(error).__name__}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 1 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
