"""Adapter-based reference core. No SMTP, SSH, timers or model calls on import."""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def load(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


@contextmanager
def exclusive(runtime):
    runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(runtime/'worker.lock', os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'a') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def validate(incident):
    """Only an allowlist of compact metadata; no arbitrary raw logs or commands."""
    if set(incident) != {'episode', 'task', 'code', 'manual_stop', 'observable'}:
        raise ValueError('Unexpected incident fields')
    for key in ('episode', 'task', 'code'):
        if not isinstance(incident[key], str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', incident[key]):
            raise ValueError('Invalid incident label')
    if type(incident['manual_stop']) is not bool or type(incident['observable']) is not bool:
        raise ValueError('Invalid observation flags')


def process(runtime, incident, authorization, notify, agent, verify, *, execute=False, now=None):
    """notify(key, payload)->bool; agent(incident)->dict; verify()->bool|None.

    notify True means transport acceptance, never human receipt. verify True is
    only a first independent good sample, never proof of sustained recovery.
    All adapters must be trusted, bounded, task-scoped code supplied by the user.
    """
    validate(incident)
    if not execute:
        return {'status':'dry_run', 'external_calls':0}
    now = time.time() if now is None else now
    runtime = Path(runtime)
    digest = hashlib.sha256(json.dumps(incident, sort_keys=True).encode()).hexdigest()
    # Episode + task + code define identity; observation flags may change.
    stable = ':'.join(incident[k] for k in ('episode', 'task', 'code'))
    key = hashlib.sha256(stable.encode()).hexdigest()
    folder = runtime/'incidents'/key
    with exclusive(runtime):
        record = load(folder/'state.json', {'status':'pending', 'attempt':0,
            'incident':incident, 'alarm_accepted':False, 'report_accepted':False,
            'first_snapshot_digest':digest})
        if record['status'] == 'running':
            # Lock ownership proves the previous worker is no longer running.
            # Do not replay uncertain remote effects or even an uncertain launch.
            record.update(status='interrupted', report={'status':'unknown',
                'summary':'Previous invocation interrupted; inspect effects before any new authorization.'})
            save(folder/'state.json', record)
        if not record['alarm_accepted']:
            save(folder/'state.json', record)
            try:
                accepted = notify(key+':alarm', {'kind':'alarm', 'incident':incident}) is True
            except Exception:
                accepted = False
            if not accepted:
                return {'status':'alarm_pending', 'attempt':record['attempt']}
            record['alarm_accepted'] = True
            save(folder/'state.json', record)
        if record['status'] == 'pending':
            permitted = (authorization.get('enabled') is True and
                authorization.get('task') == incident['task'] and
                incident['code'] in authorization.get('repair_codes', []) and
                authorization.get('allowed_changes') and not incident['manual_stop'] and
                incident['observable'])
            if not permitted:
                record.update(status='notice_only', report={'status':'not_run',
                    'summary':'Repair not authorized or evidence insufficient; manual stop preserved.'})
            else:
                day = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
                budget = load(runtime/'budget.json', {})
                limit = authorization.get('daily_limit', 6)
                if type(limit) is not int or not 1 <= limit <= 6:
                    raise ValueError('daily_limit must be 1..6')
                if budget.get(day, 0) >= limit:
                    record.update(status='budget_blocked', report={'status':'not_run',
                        'summary':'Daily shared budget exhausted.'})
                else:
                    budget[day] = budget.get(day, 0)+1
                    save(runtime/'budget.json', budget)
                    record.update(status='running', attempt=1, started_at=now)
                    save(folder/'state.json', record)  # Persist BEFORE the external call.
                    try:
                        report = agent(incident)
                        if not isinstance(report, dict):
                            raise ValueError('Invalid agent report')
                        record.update(status='reported', report=report)
                    except Exception as exc:
                        record.update(status='failed', report={'status':'unknown',
                            'summary':'Agent adapter failed; effects not confirmed.',
                            'error_type':type(exc).__name__})
                    try:
                        observed = verify()
                        record['first_independent_good_sample'] = observed is True
                        record['verification_available'] = type(observed) is bool
                    except Exception:
                        record['first_independent_good_sample'] = False
                        record['verification_available'] = False
                    # Never equate a model's "recovered" with independently recovered.
                    record['sustained_recovery_confirmed'] = False
            save(folder/'state.json', record)
        if not record['report_accepted']:
            try:
                accepted = notify(key+':report', {'kind':'repair_report', 'record':record}) is True
            except Exception:
                accepted = False
            if accepted:
                record['report_accepted'] = True
                save(folder/'state.json', record)
        return record
