"""Recovery concerns infrastructure completion, never answer correctness."""


def decide(row, attempt_no):
    failures = [f for f in row.get('provider_failures', []) if not f.get('cancelled_by_trial', False)]
    statuses = {f.get('status') for f in failures}
    if statuses & {401, 402, 403}:
        return 'external', 'Provider authorization or account failure'
    if failures:
        if any(s is not None and 400 <= s < 500 and s not in (408, 409, 425, 429) for s in statuses):
            return 'repair', 'Provider rejected the request; inspect retained request and response'
        return 'retry', 'Transient or incomplete upstream response; preserve unknown usage'
    bootstrap = row.get('preflight_failure') or {}
    if (row.get('model_launch_attempted') is False
            and bootstrap.get('preflight_verified') is False
            and bootstrap.get('ctrf_present') is False and bootstrap.get('transport_error') is True):
        return 'retry', 'Original verifier dependency download failed before model dispatch'
    terminal = row.get('agent_terminal')
    exception = row.get('exception') or {}
    if exception.get('exception_type') in ('AgentTimeoutError', 'VerifierTimeoutError') and row.get('model_launch_attempted'):
        empty_stream = [f for f in row.get('provider_failures', [])
                        if f.get('status') is None and not f.get('stream', {}).get('events')]
        if empty_stream:
            return 'retry', 'No upstream response before the original deadline; preserve separately'
        return 'complete', 'Original task deadline reached; preserve timeout and any missing verdict'
    if terminal == 'provider_error':
        return 'retry', 'Provider stopped this attempt'
    if terminal in ('process_exit', 'controller_error', 'process_error'):
        if attempt_no < 2:
            return 'retry', 'Unexpected process loss; new isolated attempt with diagnostics'
        return 'repair', 'Persistent process loss; inspect retained diagnostics'
    validation = row.get('verifier_validation') or {}
    if row.get('model_launch_attempted') and validation.get('verified') is not True:
        if validation.get('transport_error') is True and validation.get('report_sha256') is None:
            return 'retry', 'Original post-model verifier dependency transport failed; no tests ran'
        return 'repair', 'Original post-model verifier execution is missing, incomplete, or inconsistent'
    if isinstance(row.get('official_passed'), bool) and validation.get('verified') is True:
        if terminal == 'completed' and not exception:
            return 'complete', 'Executed original verifier verdict retained, including ordinary failure'
    if row.get('outcome') == 'stopped_before_model':
        return 'retry', 'No scientific model request was sent'
    text = str(row.get('error', '')) + str(exception.get('exception_message', ''))
    if 'ImageTransportError' in text:
        return 'retry', 'Official image transport failed'
    return 'repair', 'Missing complete official outcome or persistent local fault'


def backoff(attempt_no):
    return min(300, 30 * 2 ** min(max(attempt_no - 1, 0), 4))


def outcome_is_auditable(row):
    exception = row.get('exception') or {}
    if exception.get('exception_type') in ('AgentTimeoutError', 'VerifierTimeoutError') and row.get('model_launch_attempted'):
        return True
    return (row.get('agent_terminal') == 'completed' and not exception
            and (row.get('verifier_validation') or {}).get('verified') is True
            and isinstance(row.get('official_passed'), bool))


def can_admit(memory, active):
    if len(active) >= 2:
        return False
    if not active:
        return True
    return memory <= 6144 and all(m <= 6144 for m in active) and sum(active) + memory <= 6144
