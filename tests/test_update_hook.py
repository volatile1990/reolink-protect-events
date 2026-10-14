import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('owned_update_hook', Path(__file__).resolve().parents[1] / 'tools/install_update_hook.py')
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class HookTests(unittest.TestCase):
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
