"""Actual rescue error classifier only; no root, installed state or rescue run."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_vpn_rescue_system_vm as vm

ROOT = Path(__file__).resolve().parents[1]


class RescueCategoryParserTests(unittest.TestCase):
    def test_distinct_failures_survive_redaction_without_private_error_text(self):
        categories = ('installedResultTimeout', 'installedResultChanged', 'installedResultChild',
                      'installedResultSpawn', 'installedResultState', 'installedApplication',
                      'brokerDeadline','brokerCommandTimeout','brokerCommand','launchdTimeout','launchdCommand',
                      'brokerChanged','brokerOwnership','brokerState')
        rows = ['ProxyPilot VPN repair failure category: ' + name for name in categories]
        rows += ['PRIVATE ERROR /private/path', 'ProxyPilot VPN repair failure category: PRIVATE']
        self.assertEqual(vm.repair_tokens('\n'.join(rows)), ['failure:' + name for name in categories])

    def test_unified_log_projection_keeps_only_closed_result_tokens(self):
        rows = [{'eventMessage': 'ProxyPilot VPN installed result phase: readiness; category: runtime',
                 'processImagePath': '/PRIVATE', 'other': 'SECRET'},
                {'eventMessage': 'ProxyPilot VPN installed result phase: PRIVATE; category: runtime'},
                {'eventMessage': 'PRIVATE PASSWORD'}, {'eventMessage': 'x' * 513}, 7]
        result = vm.installed_result_log_tokens(json.dumps(rows))
        self.assertEqual(result, {'record': 'valid', 'events': ['readiness:runtime'], 'truncated': False})
        self.assertNotIn('PRIVATE', repr(result)); self.assertNotIn('SECRET', repr(result))

    def test_log_projection_bounds_input_and_event_count(self):
        row = {'eventMessage': 'ProxyPilot VPN installed result phase: snapshot; category: storeBusy'}
        result = vm.installed_result_log_tokens(json.dumps([row] * 100))
        self.assertEqual(len(result['events']), 96); self.assertTrue(result['truncated'])
        for text, status in [('SECRET', 'unreadable'), ('{}', 'overBudget'),
                             ('x' * 131073, 'overBudget'), (json.dumps([{}] * 513), 'overBudget')]:
            self.assertEqual(vm.installed_result_log_tokens(text), {'record': status})

    def test_host_is_refused_before_any_unified_log_query(self):
        with patch.object(vm, 'root_vm_enabled', return_value=False), patch.object(vm.subprocess, 'run') as run:
            self.assertEqual(vm.installed_result_log_diagnostics(), {'record': 'refused'})
        run.assert_not_called()

    def test_vm_query_is_fixed_and_failures_never_expose_raw_output(self):
        with patch.object(vm, 'root_vm_enabled', return_value=True), patch.object(vm.subprocess, 'run') as run:
            run.return_value = SimpleNamespace(returncode=1, stdout='PRIVATE', stderr='SECRET')
            self.assertEqual(vm.installed_result_log_diagnostics(), {'record': 'unavailable'})
            args, kwargs = run.call_args
            self.assertEqual(args[0][:7], ['/usr/bin/log', 'show', '--style', 'json', '--last', '10m', '--predicate'])
            self.assertEqual(kwargs['timeout'], 5); self.assertEqual(kwargs['env'], vm.SAFE_ENV)
            run.return_value = SimpleNamespace(returncode=0, stdout='[]', stderr='SECRET')
            self.assertEqual(vm.installed_result_log_diagnostics(),
                             {'record': 'valid', 'events': [], 'truncated': False, 'window': 'last10m'})
            run.side_effect = subprocess.TimeoutExpired('PRIVATE', 5, output='SECRET')
            self.assertEqual(vm.installed_result_log_diagnostics(), {'record': 'unavailable'})


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() != 0,
                     'Ordinary macOS compiler fixture required')
class RescueFailureCategoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-rescue-categories-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = Path(cls.folder.name) / 'checks'
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
        sources += [p for p in sorted((ROOT / 'app/vpn-helper').glob('*.swift')) if p.name not in ('ServiceMain.swift', 'VPNRescueMain.swift')]
        sources += [ROOT / 'tests/vpn_rescue_failure_category_checks.swift']
        hashes = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        captured = []
        for p in sources:
            target = Path(cls.folder.name) / 'Source' / p.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(p.read_bytes()); captured.append(str(target))
        if any(hashlib.sha256(p.read_bytes()).hexdigest() != h for p, h in hashes.items()):
            raise AssertionError('Rescue source changed during capture')
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target', arch + '-apple-macosx11.0',
            '-D', 'VPN_RESCUE_SYSTEM_ENTRY', '-D', 'VPN_EXPLICIT_RESCUE', '-D', 'VPN_RESCUE_PREPARATION',
            '-D', 'VPN_RESCUE_DIAGNOSTICS_TESTING', '-D', 'VPN_SYSTEM_ACTIVATION_DIAGNOSTICS', *captured, '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=180)
        if result.returncode: raise AssertionError(result.stderr)

    def case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'closed rescue failure categories passed\n')
        self.assertEqual(result.stderr, '')

    def test_result_failures_remain_distinct(self): self.case('result')
    def test_application_identity_has_its_own_category(self): self.case('application')
    def test_unknown_error_never_evaluates_private_description(self): self.case('unknown')
    def test_launchd_deadlines_and_rejections_are_distinct(self): self.case('launchd')




class LaunchdCommandParserTests(unittest.TestCase):
    def test_only_closed_roles_commands_outcomes_and_bounded_statuses_survive(self):
        line='ProxyPilot VPN launchd role: recovery; command: bootout; outcome: exit; status: 113'
        rows=[{'eventMessage':line,'private':'SECRET /path'},
              {'eventMessage':line.replace('recovery','PRIVATE')},
              {'eventMessage':line.replace('bootout','/private/secret')},
              {'eventMessage':line.replace('113','256')},
              {'eventMessage':line.replace('113','-1')},
              {'eventMessage':line+' SECRET'},
              {'eventMessage':line.replace('exit; status: 113','submitted; status: -1')}]
        self.assertEqual(vm.launchd_command_log_tokens(json.dumps(rows)),
            {'record':'valid','events':['recovery:bootout:exit:113','recovery:bootout:submitted:-1'],'truncated':False})
    def test_limits_and_no_raw_content(self):
        row={'eventMessage':'ProxyPilot VPN launchd role: broker; command: bootstrap; outcome: timeout; status: -1'}
        result=vm.launchd_command_log_tokens(json.dumps([row]*100))
        self.assertEqual(len(result['events']),96);self.assertTrue(result['truncated'])
        for raw,expected in [('SECRET','unreadable'),('{}','overBudget'),('x'*131073,'overBudget'),(json.dumps([{}]*513),'overBudget')]:
            self.assertEqual(vm.launchd_command_log_tokens(raw),{'record':expected})
    def test_host_refused_before_log_query(self):
        with patch.object(vm,'root_vm_enabled',return_value=False),patch.object(vm.subprocess,'run') as run:
            self.assertEqual(vm.launchd_command_log_diagnostics(),{'record':'refused'})
        run.assert_not_called()
    def test_vm_fixed_namespace_query_and_closed_failure(self):
        with patch.object(vm,'root_vm_enabled',return_value=True),patch.object(vm.subprocess,'run') as run:
            run.return_value=SimpleNamespace(returncode=0,stdout='[]',stderr='PRIVATE')
            self.assertEqual(vm.launchd_command_log_diagnostics(),{'record':'valid','events':[],'truncated':False,'window':'last10m'})
            args,kwargs=run.call_args
            self.assertEqual(args[0][-1],'subsystem == "kz.documentolog.proxypilot.vm" AND category == "launchd-command"')
            self.assertEqual(kwargs['timeout'],5);self.assertEqual(kwargs['env'],vm.SAFE_ENV)
            run.side_effect=subprocess.TimeoutExpired('PRIVATE',5,output='SECRET')
            self.assertEqual(vm.launchd_command_log_diagnostics(),{'record':'unavailable'})

if __name__ == '__main__': unittest.main()
