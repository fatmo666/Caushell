import unittest
from caushell_tb.recovery import decide, outcome_is_auditable


class RecoveryVerificationTests(unittest.TestCase):
    def row(self, **values):
        return dict(model_launch_attempted=True, agent_terminal='completed', exception=None,
                    official_passed=False, **values)

    def test_missing_verifier_does_not_become_an_answer_failure(self):
        self.assertEqual(decide(self.row(), 1)[0], 'repair')
        for reward in (True, False):
            row = self.row(verifier_validation=dict(verified=False, transport_error=True, report_sha256=None))
            row['official_passed'] = reward
            self.assertEqual(decide(row, 1)[0], 'retry')

    def test_real_failed_tests_are_retained_without_score_brushing(self):
        self.assertEqual(decide(self.row(verifier_validation=dict(verified=True)), 1)[0], 'complete')

    def test_report_inconsistency_never_becomes_blind_transport_retry(self):
        row = self.row(verifier_validation=dict(verified=False, transport_error=True, report_sha256='present'))
        self.assertEqual(decide(row, 1)[0], 'repair')

    def test_original_agent_deadline_is_not_replayed_for_missing_verdict(self):
        row = self.row(verifier_validation=dict(verified=False, transport_error=True, report_sha256=None))
        row.update(agent_terminal='harbor_cancelled', exception=dict(exception_type='AgentTimeoutError'))
        self.assertEqual(decide(row, 2)[0], 'complete')

    def test_account_errors_wait_instead_of_paid_retry(self):
        for status in (401, 402, 403):
            self.assertEqual(decide(self.row(provider_failures=[dict(status=status)]), 1)[0], 'external')

    def test_unrelated_transport_timeout_is_not_an_original_task_deadline(self):
        row = self.row(); row['exception'] = dict(exception_type='ReadTimeout')
        self.assertEqual(decide(row, 1)[0], 'repair')

    def test_final_gate_rejects_a_reward_without_a_real_verifier(self):
        self.assertFalse(outcome_is_auditable(self.row()))
        self.assertTrue(outcome_is_auditable(self.row(verifier_validation=dict(verified=True))))
        row = self.row(); row.update(agent_terminal='harbor_cancelled', exception=dict(exception_type='AgentTimeoutError'), official_passed=None)
        self.assertTrue(outcome_is_auditable(row))


if __name__ == '__main__':
    unittest.main()
