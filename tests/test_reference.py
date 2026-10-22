import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


core = module('incident_core')
codex = module('bounded_codex')


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name)/'runtime'
        self.incident = json.loads((ROOT/'examples/incident.example.json').read_text())
        self.auth = json.loads((ROOT/'examples/authorization.example.json').read_text())
        self.auth['enabled'] = True
        self.calls = []

    def notify(self, key, payload):
        self.calls.append(payload['kind'])
        return True

    def agent(self, incident):
        self.calls.append('agent')
        return {'status':'recovered', 'summary':'synthetic result'}

    def verify(self):
        self.calls.append('verify')
        return True

    def run_one(self, **kwargs):
        return core.process(self.runtime, self.incident, self.auth,
            kwargs.pop('notify',self.notify), kwargs.pop('agent',self.agent),
            kwargs.pop('verify',self.verify), execute=kwargs.pop('execute',True), now=10000, **kwargs)

    def test_default_dry_run_has_no_files_or_callbacks(self):
        self.assertEqual(self.run_one(execute=False)['status'],'dry_run')
        self.assertEqual(self.calls,[])
        self.assertFalse(self.runtime.exists())

    def test_alarm_acceptance_required_before_agent(self):
        value=self.run_one(notify=lambda *_:False)
        self.assertEqual(value['status'],'alarm_pending')
        self.assertEqual(self.calls,[])

    def test_alarm_exception_does_not_call_agent(self):
        def failure(*_):raise TimeoutError('synthetic transport failure')
        self.assertEqual(self.run_one(notify=failure)['status'],'alarm_pending')
        self.assertEqual(self.calls,[])

    def test_alarm_agent_verify_report_order(self):
        value=self.run_one()
        self.assertEqual(self.calls,['alarm','agent','verify','repair_report'])
        self.assertEqual(value['attempt'],1)
        self.assertFalse(value['sustained_recovery_confirmed'])

    def test_repeated_event_does_not_repeat_agent(self):
        self.run_one();self.run_one()
        self.assertEqual(self.calls.count('agent'),1)
        self.assertEqual(self.calls.count('alarm'),1)

    def test_disabled_authorization_is_notice_only(self):
        self.auth['enabled']=False
        self.assertEqual(self.run_one()['status'],'notice_only')
        self.assertNotIn('agent',self.calls)

    def test_wrong_task_cannot_borrow_authorization(self):
        self.auth['task']='another-task'
        self.assertEqual(self.run_one()['status'],'notice_only')

    def test_manual_stop_is_never_resumed(self):
        self.incident['manual_stop']=True
        self.assertEqual(self.run_one()['status'],'notice_only')
        self.assertNotIn('agent',self.calls)

    def test_unobservable_is_not_treated_as_dead_task(self):
        self.incident['observable']=False
        self.assertEqual(self.run_one()['status'],'notice_only')

    def test_different_code_not_implicitly_authorized(self):
        self.incident['code']='solver_failure'
        self.assertEqual(self.run_one()['status'],'notice_only')

    def test_daily_budget_is_shared_between_events(self):
        core.save(self.runtime/'budget.json',{'1970-01-01':6})
        self.assertEqual(self.run_one()['status'],'budget_blocked')
        self.assertNotIn('agent',self.calls)

    def test_interrupted_attempt_never_replayed(self):
        self.run_one()
        path=next((self.runtime/'incidents').glob('*/state.json'))
        value=core.load(path);value['status']='running';value['report_accepted']=False
        core.save(path,value);self.calls.clear()
        self.assertEqual(self.run_one()['status'],'interrupted')
        self.assertNotIn('agent',self.calls)

    def test_report_retry_does_not_repeat_repair(self):
        self.run_one(notify=lambda key,p:p['kind']=='alarm')
        self.calls.clear();self.run_one()
        self.assertEqual(self.calls,['repair_report'])

    def test_agent_error_preserves_unknown_effects_and_no_replay(self):
        def failure(*_):raise TimeoutError('synthetic')
        self.assertEqual(self.run_one(agent=failure)['status'],'failed')
        self.calls.clear();self.run_one()
        self.assertNotIn('agent',self.calls)

    def test_verifier_error_never_confirms_recovery(self):
        def failure():raise TimeoutError('synthetic')
        value=self.run_one(verify=failure)
        self.assertFalse(value['verification_available'])
        self.assertFalse(value['sustained_recovery_confirmed'])

    def test_lock_blocks_concurrent_worker(self):
        with core.exclusive(self.runtime):
            with self.assertRaises(BlockingIOError):self.run_one()
        self.assertEqual(self.calls,[])

    def test_raw_logs_or_path_traversal_not_accepted(self):
        self.incident['raw_log']='not allowed'
        with self.assertRaises(ValueError):self.run_one()
        del self.incident['raw_log'];self.incident['episode']='../escape'
        with self.assertRaises(ValueError):self.run_one()


class CodexAdapterTests(unittest.TestCase):
    def test_no_unrestricted_sandbox_or_parent_environment_inheritance(self):
        with tempfile.TemporaryDirectory(prefix='incident-') as folder:
            workspace=Path(folder)
            fake=mock.Mock(returncode=0)
            report={'status':'blocked','summary':'synthetic','changes':[], 'verification':[], 'remaining':[]}
            def respond(*_,**__):(workspace/'model_report.json').write_text(json.dumps(report))
            fake.communicate.side_effect=respond
            with mock.patch.object(codex.subprocess,'Popen',return_value=fake) as launch:
                result=codex.run({},workspace=workspace,model='example-model',allowed_changes=['synthetic only'],child_env={'PATH':'/usr/bin'})
            args=launch.call_args.args[0]
            self.assertIn('read-only',args)
            self.assertNotIn('danger-full-access',args)
            self.assertIn('--ignore-user-config',args)
            self.assertEqual(launch.call_args.kwargs['env'],{'PATH':'/usr/bin'})
            self.assertEqual(result['status'],'blocked')

    def test_timeout_kills_only_agent_process_group(self):
        with tempfile.TemporaryDirectory(prefix='incident-') as folder:
            fake=mock.Mock(pid=87654321)
            fake.communicate.side_effect=[subprocess.TimeoutExpired('synthetic',1),None]
            with mock.patch.object(codex.subprocess,'Popen',return_value=fake), mock.patch.object(codex.os,'killpg') as kill:
                with self.assertRaises(TimeoutError):
                    codex.run({},workspace=folder,model='example-model',allowed_changes=['synthetic'],child_env={},timeout=1)
            kill.assert_called_once_with(87654321,codex.signal.SIGTERM)

    def test_report_schema_is_validated(self):
        with self.assertRaises(ValueError):codex.validate_report({'status':'recovered'})

    def test_production_root_or_unbounded_mode_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ordinary-') as folder:
            with self.assertRaises(ValueError):codex.run({},workspace=folder,model='example-model',allowed_changes=['synthetic'],child_env={})
            with self.assertRaises(ValueError):codex.run({},workspace=folder,model='example-model',allowed_changes=['synthetic'],child_env={},sandbox='danger-full-access')


if __name__=='__main__':unittest.main()
