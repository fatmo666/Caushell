import json
from pathlib import Path
import tempfile
import unittest

from caushell_tb.verification import inspect_verifier


class VerificationTests(unittest.TestCase):
    def run_report(self, statuses, reward, **extra):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'verifier').mkdir()
            (root/'verifier/ctrf.json').write_text(json.dumps(dict(results=dict(
                tests=[dict(name=str(i), status=s) for i, s in enumerate(statuses)], **extra))))
            return inspect_verifier(root, dict(reward=reward))

    def test_real_pass_and_real_answer_failure_are_both_valid(self):
        self.assertTrue(self.run_report(['passed'], 1)['verified'])
        self.assertTrue(self.run_report(['passed', 'failed'], 0)['verified'])

    def test_missing_report_with_zero_reward_is_not_an_answer_verdict(self):
        for text in ['E: Failed to fetch URL Unable to connect',
                     'Failed to download distribution due to network timeout']:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); (root/'verifier').mkdir()
                (root/'verifier/test-stdout.txt').write_text(text)
                value = inspect_verifier(root, dict(reward=0))
                self.assertFalse(value['verified'])
                self.assertTrue(value['transport_error'])

    def test_unknown_missing_report_does_not_invent_transport_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            value = inspect_verifier(directory, dict(reward=0))
            self.assertFalse(value['verified']); self.assertFalse(value['transport_error'])

    def test_empty_skipped_pending_and_malformed_reports_stay_unverified(self):
        for statuses in ([], ['skipped'], ['pending'], ['other']):
            with self.subTest(statuses=statuses):
                self.assertFalse(self.run_report(statuses, 0)['verified'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'verifier').mkdir()
            (root/'verifier/ctrf.json').write_text('{')
            self.assertFalse(inspect_verifier(root, dict(reward=0))['verified'])

    def test_reward_must_match_executed_tests_not_untrusted_summary_counts(self):
        self.assertFalse(self.run_report(['failed'], 1)['verified'])
        self.assertFalse(self.run_report(['passed'], 0)['verified'])
        self.assertFalse(self.run_report(['passed'], None)['verified'])
        self.assertFalse(self.run_report(['passed'], True)['verified'])
        self.assertTrue(self.run_report(['failed'], 0, summary=dict(passed=99))['verified'])

    def test_failed_real_tests_do_not_retry_due_to_old_download_log_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'verifier').mkdir()
            (root/'verifier/test-stdout.txt').write_text('Failed to download due to network timeout')
            (root/'verifier/ctrf.json').write_text(json.dumps(dict(results=dict(tests=[dict(status='failed')]))))
            value = inspect_verifier(root, dict(reward=0))
            self.assertTrue(value['verified']); self.assertFalse(value['transport_error'])

    def test_symlink_report_is_not_an_admission_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'verifier').mkdir()
            target = root/'elsewhere.json'
            target.write_text(json.dumps(dict(results=dict(tests=[dict(status='passed')]))))
            (root/'verifier/ctrf.json').symlink_to(target)
            self.assertFalse(inspect_verifier(root, dict(reward=1))['verified'])


if __name__ == '__main__':
    unittest.main()
