import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('owned_update_hook', Path(__file__).resolve().parents[1] / 'tools/install_update_hook.py')
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class HookTests(unittest.TestCase):
    def fixture(self, root):
        events, bridge = root / 'events', root / 'bridge'
        for repo in (events, bridge):
            (repo / '.git/hooks').mkdir(parents=True)
        (events / 'tools').mkdir()
        for name in ('serverrelease.py', 'protect_ops.py'):
            (events / 'tools' / name).write_text('# offline fixture\n')
        config = root / 'private-paths.json'
        config.write_text(json.dumps({'eventsRepo': str(events), 'bridgeRepo': str(bridge)}))
        return events, bridge, config

    def test_events_scope_replaces_only_owned_events_hook_and_preserves_bridge(self):
        with tempfile.TemporaryDirectory() as folder:
            events, bridge, config = self.fixture(Path(folder))
            event_hook = events / '.git/hooks/pre-push'
            event_hook.write_text(hook.MARKER + '\nold events hook\n')
            bridge_hook = bridge / '.git/hooks/pre-push'
            bridge_hook.write_text('unrelated existing bridge hook\n')
            with patch.object(hook.subprocess, 'check_output', return_value='.git/hooks/pre-push'), \
                 contextlib.redirect_stdout(io.StringIO()):
                hook.main(['--config', str(config)])
            self.assertIn('serverrelease.py', event_hook.read_text())
            self.assertNotIn('--config', event_hook.read_text())
            self.assertEqual(bridge_hook.read_text(), 'unrelated existing bridge hook\n')

    def test_both_scopes_keep_distinct_controllers_and_bridge_config(self):
        with tempfile.TemporaryDirectory() as folder:
            events, bridge, config = self.fixture(Path(folder))
            with patch.object(hook.subprocess, 'check_output', return_value='.git/hooks/pre-push'), \
                 contextlib.redirect_stdout(io.StringIO()):
                hook.main(['--config', str(config), '--scope', 'both'])
            event_text = (events / '.git/hooks/pre-push').read_text()
            bridge_text = (bridge / '.git/hooks/pre-push').read_text()
            self.assertIn('serverrelease.py', event_text)
            self.assertNotIn('protect_ops.py', event_text)
            self.assertIn('protect_ops.py', bridge_text)
            self.assertIn('--config', bridge_text)
            self.assertNotIn('serverrelease.py', bridge_text)

    def test_unowned_later_hook_refusal_does_not_partially_change_earlier_hook(self):
        with tempfile.TemporaryDirectory() as folder:
            events, bridge, config = self.fixture(Path(folder))
            event_hook = events / '.git/hooks/pre-push'; event_hook.write_text(hook.MARKER + '\noriginal\n')
            bridge_hook = bridge / '.git/hooks/pre-push'; bridge_hook.write_text('unowned\n')
            with patch.object(hook.subprocess, 'check_output', return_value='.git/hooks/pre-push'):
                with self.assertRaisesRegex(RuntimeError, 'existing_unowned_hook_preserved'):
                    hook.main(['--config', str(config), '--scope', 'both'])
            self.assertEqual(event_hook.read_text(), hook.MARKER + '\noriginal\n')
            self.assertEqual(bridge_hook.read_text(), 'unowned\n')

    @unittest.skipUnless(os.name != 'nt' and shutil.which('sh') and shutil.which('git'), 'POSIX hook execution')
    def test_only_current_main_push_runs_controller_and_failure_blocks_push(self):
        with tempfile.TemporaryDirectory(prefix='hook spaces ') as folder:
            root = Path(folder)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture', '--allow-empty'], check=True)
            commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            called = root / 'called'
            controller = root / 'controller file.py'
            controller.write_text('from pathlib import Path\nPath(' + repr(str(called)) + ').write_text("called")\nraise SystemExit(13)\n')
            path = root / 'pre-push'
            path.write_text(hook.hook_text(__import__('sys').executable, controller, root / 'config file.json'))
            branch = 'refs/heads/feature ' + commit + ' refs/heads/feature ' + '0' * 40 + '\n'
            result = subprocess.run(['sh', str(path)], input=branch, text=True, cwd=root)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(called.exists())
            main = 'refs/heads/main ' + commit + ' refs/heads/main ' + '0' * 40 + '\n'
            result = subprocess.run(['sh', str(path)], input=main, text=True, cwd=root)
            self.assertEqual(result.returncode, 13)
            self.assertTrue(called.exists())

    def test_shell_paths_are_quoted_including_spaces_and_dollar_characters(self):
        text = hook.hook_text('/safe/python', '/safe/my script.py', '/safe/config $not-a-command.json')
        self.assertIn("'/safe/my script.py'", text)
        self.assertIn("'/safe/config $not-a-command.json'", text)
        self.assertIn('refs/heads/main', text)
