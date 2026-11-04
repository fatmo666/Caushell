"""A reward receipt is not proof that the original verifier ran its tests."""
import hashlib
import json
from pathlib import Path
import stat


def _read(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError('Verifier artifact is not a bounded regular file')
    return path.read_bytes()


def inspect_verifier(output, rewards):
    """Validate the original CTRF artifact, without changing tests or reward."""
    root = Path(output) / 'verifier'
    report = root / 'ctrf.json'
    result = dict(verified=False, reason='Missing original CTRF report', ctrf=str(report),
                  raw_rewards=rewards, report_sha256=None, transport_error=False, logs=[])
    # These are diagnostics only. They never replace a real test report.
    for name in ('test-stdout.txt', 'test-stderr.txt'):
        path = root / name
        if not path.exists():
            continue
        try:
            raw = _read(path, 16 * 1024 * 1024)
            tail = raw[-65536:].decode(errors='replace')
            lower = tail.lower()
            signatures = [('failed to fetch', 'unable to connect'),
                          ('failed to fetch', 'temporary failure resolving'),
                          ('curl:', 'could not resolve host'),
                          ('failed to download', 'error sending request'),
                          ('failed to download', 'network timeout')]
            matched = [list(pair) for pair in signatures if all(s in lower for s in pair)]
            result['logs'].append(dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                                       bytes=len(raw), signatures=matched, tail=tail[-4000:]))
            result['transport_error'] |= bool(matched)
        except (OSError, ValueError) as error:
            result['logs'].append(dict(path=str(path), error=str(error)))
    if not report.exists():
        return result
    # If a report exists, transport-looking log text alone cannot justify retry.
    result['transport_error'] = False
    try:
        raw = _read(report, 16 * 1024 * 1024)
        result['report_sha256'] = hashlib.sha256(raw).hexdigest()
        tests = json.loads(raw)['results']['tests']
        if not isinstance(tests, list) or not tests:
            raise ValueError('No original tests collected')
        counts = {key: 0 for key in ('passed', 'failed', 'skipped')}
        for test in tests:
            status = test.get('status') if isinstance(test, dict) else None
            if status not in counts:
                raise ValueError('Unfinished or invalid original test result')
            counts[status] += 1
        if counts['passed'] + counts['failed'] == 0:
            raise ValueError('No original tests executed')
        reward = rewards.get('reward') if isinstance(rewards, dict) else rewards
        if isinstance(reward, bool) or not isinstance(reward, (int, float)) or reward not in (0, 1):
            raise ValueError('Missing binary official reward receipt')
        if bool(reward) != (counts['failed'] == 0):
            raise ValueError('Official reward disagrees with original test results')
        result.update(verified=True, reason='Original tests collected and executed', tests=counts)
    except (OSError, ValueError, TypeError, KeyError) as error:
        result['reason'] = str(error)
    return result
