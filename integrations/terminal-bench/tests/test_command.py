import json
import os
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from caushell_tb.harbor_agent import command_factory

class CommandTests(unittest.TestCase):
    def test_native_client_preserves_original_context_and_has_no_inference_caps(self):
        class Model:url='http://mock'
        cfg=dict(docker='docker',asset_mount='/tmp/.caushell-harness-x',commands=dict(claude=['{assets}/claude']),system_prompt='prefer Bash')
        build=command_factory(cfg,'a'*64,None,'/tmp/settings','/tmp/sessions',{'CUSTOM':'native','PATH':'/phase-bin'},'/root','/phase-bin:/usr/bin','/work')
        command,host_env=build(Path('/host/evidence'),Model(),'session',Path('/root'),dict(usage_kind='local',model='local',environment={},tools='default'))
        self.assertNotIn('--user',command);self.assertEqual(command[command.index('--workdir')+1],'/work')
        self.assertIn('HOME=/root',command);self.assertIn('PATH=/phase-bin:/usr/bin',command);self.assertIn('CUSTOM=native',command)
        self.assertNotIn('--max-turns',command);self.assertNotIn('--max-budget-usd',command)
        self.assertFalse(any('MAX_THINKING_TOKENS=' in x for x in command))
        self.assertEqual(command[command.index('--settings')+1],'/tmp/settings')
        self.assertIn('/tmp/.caushell-harness-x/claude',command)
        self.assertNotIn('/usr/local/bin/claude',command)
        self.assertNotIn('LD_PRELOAD=',command)

if __name__=='__main__':unittest.main()
