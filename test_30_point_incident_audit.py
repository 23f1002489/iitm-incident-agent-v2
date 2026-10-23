"""Offline contract audit for Incident Agent v2. No AI Pipe or Neon calls.
Place beside app/main.py; run: python test_seven_category_audit.py
This is a contract regression suite, NOT a hidden-grader replica.
"""
import copy
import importlib.util
import json
import hashlib
import re
import os
import tempfile
import unittest
import uuid
from pathlib import Path

TMP = tempfile.TemporaryDirectory(prefix='ga5_audit_')
os.environ['DATABASE_URL'] = 'sqlite:///' + str(Path(TMP.name) / 'audit.db')
os.environ['AI_PIPE_TOKEN'] = 'OFFLINE_FAKE_TOKEN_DO_NOT_EXPORT'
ROOT = Path(__file__).resolve().parent
APP_PATH = ROOT / 'app' / 'main.py'
if not APP_PATH.exists():
    APP_PATH = ROOT / 'main_transport_diagnostics.py'
if not APP_PATH.exists():
    raise SystemExit('Place this script in the project root beside app/main.py')
spec = importlib.util.spec_from_file_location('audit_agent', APP_PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
from fastapi.testclient import TestClient

SECRET = 'PRIVATE_CANARY_NEVER_EXPORT_7788'
CALLS = []
MODE = {'diagnostics': 2, 'effect': 'page_owner'}

async def fake_plan(payload, incident, catalog, policy):
    CALLS.append(payload['runId'])
    n = MODE['diagnostics']
    ds = [
        {'toolName': 'query_logs', 'arguments': {'service': 'billing', 'query': 'pool timeout', 'windowMinutes': 15}, 'evidence': ['ev1']},
        {'toolName': 'query_metrics', 'arguments': {'service': 'billing', 'metric': 'db_pool_wait', 'windowMinutes': 15}, 'evidence': ['ev2']},
    ][:n]
    effect = MODE['effect']
    args = {'service': 'billing', 'severity': 'SEV-1'} if effect == 'page_owner' else {'service': 'billing', 'release': 'release-12'}
    return {'rootCause': 'database_connection_exhaustion', 'evidence': ['ev1','ev2']}, ds, {'toolName': effect, 'arguments': args}
m.plan_original = m.plan
m.plan = fake_plan

def payload():
    return {
        'profile':'ga5-incident-agent/v2', 'runId':'audit_'+uuid.uuid4().hex,
        'agentName':'incident-response','publicMarker':'PUBLIC_MARKER_AUDIT',
        'sensitive':{'accessToken':SECRET,'privateNote':SECRET},
        'incident':{'incidentId':'incident-1','title':'DB pool exhausted','service':'billing','severity':'SEV-1',
                    'transcript':'[ev1] connection pool wait timeout\n[ev2] normal CPU and traffic',
                    'allowedRootCauses':['database_connection_exhaustion','traffic_capacity_exhaustion']},
        'toolCatalog':[
            {'name':'query_logs','description':'Logs','inputSchema':{'type':'object','required':['service','query','windowMinutes'],
                'properties':{'service':{'type':'string'},'query':{'type':'string'},'windowMinutes':{'type':'integer'}},'additionalProperties':False}},
            {'name':'query_metrics','description':'Metrics','inputSchema':{'type':'object','required':['service','metric','windowMinutes'],
                'properties':{'service':{'type':'string'},'metric':{'type':'string'},'windowMinutes':{'type':'integer'}},'additionalProperties':False}},
            {'name':'page_owner','description':'Page','inputSchema':{'type':'object','required':['service','severity'],
                'properties':{'service':{'type':'string'},'severity':{'type':'string'}},'additionalProperties':False}},
            {'name':'rollback_deployment','description':'Rollback','inputSchema':{'type':'object','required':['service','release'],
                'properties':{'service':{'type':'string'},'release':{'type':'string'}},'additionalProperties':False}},
        ],
        'policy':{'maximumDiagnostics':3,'effectTools':['page_owner','rollback_deployment'],
                  'approvalRequiredFor':['rollback_deployment'],'doNotExport':[SECRET]}
    }

def outcome(d, status=200, error_type=None):
    item = {'actionId':d['actionId'],'callId':d['callId'],'attempt':d['attempt'],
            'status':status,'resultClass':'diagnosis_confirmed' if status==200 else 'error', 'nonce':uuid.uuid4().hex}
    if error_type: item['errorType'] = error_type
    return item

def receipt(c, rid, ds, receipt_id=None):
    return c.post(f'/v2/incidents/{rid}/receipts',json={'receiptId':receipt_id or uuid.uuid4().hex,'outcomes':[outcome(d) for d in ds]})

def spans(st):
    return st['otlp']['resourceSpans'][0]['scopeSpans'][0]['spans']

def attrs(s):
    return {a['key']: next(iter(a['value'].values())) for a in s.get('attributes',[])}

class SevenCategoryAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(m.app)
        cls.client.__enter__()
    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.__exit__(None, None, None)
        finally:
            # Windows locks SQLite files while pooled connections remain open.
            m.engine.dispose()
            TMP.cleanup()
    def setUp(self):
        MODE.update(diagnostics=2,effect='page_owner')
    def create(self, p=None):
        p=p or payload()
        r=self.client.post('/v2/incidents',json=p)
        self.assertEqual(r.status_code,200,r.text[:300])
        return p,r.json()
    def complete(self,p,first):
        r=receipt(self.client,p['runId'],first['dispatches'])
        self.assertEqual(r.status_code,200,r.text[:300])
        nxt=r.json()
        self.assertEqual(len(nxt['dispatches']),1)
        last=receipt(self.client,p['runId'],nxt['dispatches'])
        self.assertEqual(last.status_code,200,last.text[:300])
        return last.json()

    def test_01_proposal_shape_and_evidence(self):
        p,st=self.create()
        self.assertIn(st['diagnosis']['rootCause'],p['incident']['allowedRootCauses'])
        self.assertEqual(len(st['diagnosis']['evidence']),len(set(st['diagnosis']['evidence'])))
        self.assertTrue(2<=len(st['diagnosis']['evidence'])<=4)
        self.assertTrue(1<=len(st['dispatches'])<=p['policy']['maximumDiagnostics'])
        for d in st['dispatches']:
            self.assertTrue(d['evidence'])
            self.assertTrue(set(d['evidence']).issubset(st['diagnosis']['evidence']))

    def test_02_semantics_exact_arguments_and_effect(self):
        p,st=self.create()
        self.assertEqual({d['toolName'] for d in st['dispatches']},{'query_logs','query_metrics'})
        expected={'query_logs':{'service':'billing','query':'pool timeout','windowMinutes':15},
                  'query_metrics':{'service':'billing','metric':'db_pool_wait','windowMinutes':15}}
        for d in st['dispatches']:
            self.assertEqual(d['arguments'],expected[d['toolName']])
        done=self.complete(p,st)
        self.assertEqual(done['chosenEffect'],'page_owner')
        self.assertEqual(done['actionLog'][-1]['arguments'],{'service':'billing','severity':'SEV-1'})
        # Exact assertions here validate the mock scenario, NOT actual AI choices.

    def test_03_topology_exact_counts_and_client_correlation(self):
        p,st=self.create()
        done=self.complete(p,st)
        ss=spans(done)
        self.assertEqual(len(ss),10)
        by_name={s['name']:s for s in ss}
        self.assertEqual(sum(s['name']=='chat incident-plan' for s in ss),1)
        self.assertEqual(sum(s['name']=='incident.join' for s in ss),1)
        self.assertEqual(len({s['spanId'] for s in ss}),len(ss))
        self.assertEqual(len({s['traceId'] for s in ss}),1)
        server=by_name['POST /v2/incidents']
        agent=by_name['invoke_agent incident-response']
        self.assertEqual(agent['parentSpanId'],server['spanId'])
        self.assertEqual(by_name['chat incident-plan']['parentSpanId'],agent['spanId'])
        self.assertEqual(len(by_name['incident.join']['links']),2)
        for s in ss:
            a=attrs(s)
            self.assertEqual(a['ga5.run.id'],p['runId'])
            self.assertEqual(a['ga5.public.marker'],p['publicMarker'])
        for d in done['actionLog']:
            sid=d['traceparent'].split('-')[2]
            matched=[s for s in ss if s['spanId']==sid]
            self.assertEqual(len(matched),1)
            self.assertEqual(matched[0]['kind'],3)
            a=attrs(matched[0]);self.assertEqual(a['ga5.action.id'],d['actionId'])
            self.assertEqual(int(a['ga5.attempt']),d['attempt'])
            self.assertEqual(int(a['http.request.resend_count']),d['attempt']-1)

    def test_04_correlation_receipts_and_replay(self):
        p,st=self.create()
        calls=CALLS.count(p['runId'])
        replay=self.client.post('/v2/incidents',json=p)
        self.assertEqual(replay.json(),st)
        self.assertEqual(CALLS.count(p['runId']),calls)
        d=st['dispatches'][0]
        rid='receipt_'+uuid.uuid4().hex
        body={'receiptId':rid,'outcomes':[outcome(d)]}
        a=self.client.post(f'/v2/incidents/{p["runId"]}/receipts',json=body)
        self.assertEqual(a.status_code,200)
        self.assertEqual(self.client.post(f'/v2/incidents/{p["runId"]}/receipts',json=body).json(),a.json())
        bad=copy.deepcopy(body);bad['outcomes'][0]['nonce']='changed'
        self.assertEqual(self.client.post(f'/v2/incidents/{p["runId"]}/receipts',json=bad).status_code,409)
        self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(),a.json())

    def test_05_lifecycle_503_timeout_and_approval(self):
        p,st=self.create()
        d1,d2=st['dispatches']
        r=self.client.post(f'/v2/incidents/{p["runId"]}/receipts',json={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d1,503)]})
        self.assertEqual(r.status_code,200)
        retry=r.json()['dispatches'][0]
        self.assertEqual(retry['actionId'],d1['actionId'])
        self.assertEqual(retry['callId'],d1['callId'])
        self.assertEqual(retry['attempt'],2)
        self.assertNotEqual(retry['traceparent'],d1['traceparent'])
        r2=receipt(self.client,p['runId'],[retry,d2])
        self.assertEqual(r2.status_code,200)
        self.assertEqual(r2.json()['dispatches'][0]['phase'],'effect')
        receipt(self.client,p['runId'],r2.json()['dispatches'])
        final=self.client.get(f'/v2/incidents/{p["runId"]}').json()
        toolsp=[s for s in spans(final) if s['name']=='POST tool/query_logs']
        self.assertEqual(len(toolsp),2)
        self.assertEqual(attrs(toolsp[0])['error.type'],'503')
        self.assertEqual(toolsp[0]['status']['code'],2)
        p2,st2=self.create()
        t=self.client.post(f'/v2/incidents/{p2["runId"]}/receipts',json={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(st2['dispatches'][0],0,'timeout'),outcome(st2['dispatches'][1])]})
        self.assertEqual(t.status_code,200)
        self.assertEqual(t.json()['status'],'failed')
        self.assertFalse(t.json().get('dispatches'))
        self.assertIn('page_owner',t.json()['suppressed'])
        MODE['effect']='rollback_deployment'
        p3,st3=self.create()
        gate=receipt(self.client,p3['runId'],st3['dispatches']).json()
        self.assertFalse(gate['dispatches'])
        self.assertEqual(len(gate['approvals']),1)
        a=gate['approvals'][0]
        self.assertEqual(a['argumentsDigest'],m.digest({'service':'billing','release':'release-12'}))
        approved=self.client.post(f'/v2/incidents/{p3["runId"]}/receipts',json={'receiptId':uuid.uuid4().hex,'approvals':[{'approvalId':a['approvalId'],'decision':'approved','nonce':'audit-nonce'}]})
        self.assertEqual(approved.status_code,200)
        effect=approved.json()['dispatches'][0]
        self.assertEqual(effect['actionId'],a['actionId'])
        self.assertEqual(effect['approvalId'],a['approvalId'])
        self.assertEqual(effect['approvalNonce'],'audit-nonce')

    def test_06_durability_changed_content_and_terminal_get(self):
        p,st=self.create()
        altered=copy.deepcopy(p);altered['policy']['additionalAuditConstraint']='changed'
        self.assertEqual(self.client.post('/v2/incidents',json=altered).status_code,409)
        altered=copy.deepcopy(p);altered['toolCatalog'][0]['description']='changed'
        self.assertEqual(self.client.post('/v2/incidents',json=altered).status_code,409)
        final=self.complete(p,st)
        self.assertEqual(final['status'],'completed')
        self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(),final)
        self.assertEqual(self.client.post('/v2/incidents',json=p).json(),final)
        self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(),final)

    def test_07_redaction_of_exported_state_and_otlp(self):
        p,st=self.create()
        final=self.complete(p,st)
        dumped=json.dumps(final)
        for secret in [SECRET,'OFFLINE_FAKE_TOKEN_DO_NOT_EXPORT',p['incident']['transcript']]:
            self.assertNotIn(secret,dumped)
        for s in spans(final):
            a=attrs(s)
            self.assertNotIn('gen_ai.tool.call.arguments',a)
            self.assertNotIn('gen_ai.tool.call.result',a)
            self.assertNotIn('authorization',a)
        self.assertEqual(len(final['actionLog']),3)
        self.assertEqual(len(final['receiptLog']),3)

    def test_08_advanced_changed_content_conflicts(self):
        p, first = self.create()
        baseline = self.client.get(f'/v2/incidents/{p["runId"]}').json()
        for field, value in [('transcript', '[ev1] changed\n[ev2] changed'), ('incidentId', 'different-incident')]:
            changed = copy.deepcopy(p)
            changed['incident'][field] = value
            r = self.client.post('/v2/incidents', json=changed)
            self.assertEqual(r.status_code, 409, (field, r.text))
            self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(), baseline)
        d = first['dispatches'][0]
        body = {'receiptId': 'receipt_'+uuid.uuid4().hex, 'outcomes': [outcome(d)]}
        r = self.client.post(f'/v2/incidents/{p["runId"]}/receipts', json=body)
        self.assertEqual(r.status_code, 200, r.text)
        snapshot = self.client.get(f'/v2/incidents/{p["runId"]}').json()
        modified = copy.deepcopy(body)
        modified['outcomes'][0]['status'] = 503
        conflict = self.client.post(f'/v2/incidents/{p["runId"]}/receipts', json=modified)
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(), snapshot)

    def test_09_advanced_retry_resend_and_new_client_span(self):
        p, first = self.create()
        d = first['dispatches'][0]
        r = self.client.post(f'/v2/incidents/{p["runId"]}/receipts', json={
            'receiptId':uuid.uuid4().hex, 'outcomes':[outcome(d, 503, '503')]})
        self.assertEqual(r.status_code, 200, r.text)
        state = r.json()
        self.assertEqual(state['approvals'], [])
        self.assertEqual(len(state['dispatches']), 1)
        retry = state['dispatches'][0]
        self.assertEqual((retry['actionId'],retry['callId']), (d['actionId'],d['callId']))
        self.assertEqual(retry['attempt'], 2)
        self.assertNotEqual(retry['traceparent'].split('-')[2], d['traceparent'].split('-')[2])
        r = receipt(self.client, p['runId'], [retry, first['dispatches'][1]])
        self.assertEqual(r.status_code, 200, r.text)
        effect = r.json()['dispatches']
        self.assertEqual(len(effect), 1)
        done = receipt(self.client, p['runId'], effect).json()
        attempts = [s for s in spans(done) if s['name']=='POST tool/'+d['toolName']]
        self.assertEqual(len(attempts), 2)
        attempts.sort(key=lambda s: int(attrs(s)['ga5.attempt']))
        for i, dispatch in enumerate([d,retry]):
            span = attempts[i]
            self.assertEqual(span['spanId'], dispatch['traceparent'].split('-')[2])
            self.assertEqual(int(attrs(span)['http.request.resend_count']), i)
            self.assertEqual(int(attrs(span)['ga5.attempt']), i+1)
        self.assertEqual(attempts[0]['status']['code'], 2)
        self.assertEqual(attrs(attempts[0])['error.type'], '503')
        self.assertNotIn('error.type', attrs(attempts[1]))

    def test_10_advanced_timeout_suppresses_destructive_effect(self):
        MODE['effect'] = 'rollback_deployment'
        p, first = self.create()
        ds = first['dispatches']
        r = self.client.post(f'/v2/incidents/{p["runId"]}/receipts', json={
            'receiptId':uuid.uuid4().hex, 'outcomes':[outcome(ds[0], 0, 'timeout'), outcome(ds[1])]})
        self.assertEqual(r.status_code, 200, r.text)
        done = r.json()
        self.assertEqual(done['status'], 'failed')
        self.assertFalse(done.get('dispatches'))
        self.assertFalse(done.get('approvals'))
        self.assertIn('rollback_deployment', done['suppressed'])
        self.assertFalse(any(d['phase']=='effect' for d in done['actionLog']))
        self.assertTrue(any(x.get('status')==0 for x in done['receiptLog']))
        timed = [s for s in spans(done) if s['spanId']==ds[0]['traceparent'].split('-')[2]]
        self.assertEqual(len(timed), 1)
        self.assertEqual(timed[0]['status']['code'], 2)
        self.assertEqual(attrs(timed[0])['error.type'], 'timeout')
        self.assertEqual(self.client.get(f'/v2/incidents/{p["runId"]}').json(), done)

    def test_11_advanced_approval_digest_and_nonce(self):
        MODE['effect'] = 'rollback_deployment'
        p, first = self.create()
        gate = receipt(self.client, p['runId'], first['dispatches']).json()
        self.assertEqual(gate['dispatches'], [])
        self.assertEqual(len(gate['approvals']), 1)
        approval = gate['approvals'][0]
        self.assertTrue(re.fullmatch(r'[0-9a-f]{64}', approval['argumentsDigest']))
        self.assertGreaterEqual(len(approval['approvalId']), 8)
        args = {'service':'billing','release':'release-12'}
        expected = hashlib.sha256(json.dumps(args,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(approval['argumentsDigest'], expected)
        nonce = 'test-approval-'+uuid.uuid4().hex
        body = {'receiptId':uuid.uuid4().hex, 'approvals':[
            {'approvalId':approval['approvalId'], 'decision':'approved', 'nonce':nonce}]}
        r = self.client.post(f'/v2/incidents/{p["runId"]}/receipts', json=body)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(r.json()['dispatches']), 1)
        dispatched = r.json()['dispatches'][0]
        self.assertEqual(dispatched['actionId'], approval['actionId'])
        self.assertEqual(dispatched['approvalId'], approval['approvalId'])
        self.assertEqual(dispatched['approvalNonce'], nonce)
        done = receipt(self.client, p['runId'], [dispatched]).json()
        gate_spans = [s for s in spans(done) if s['name']=='approval_gate']
        self.assertEqual(len(gate_spans), 1)
        self.assertEqual(attrs(gate_spans[0])['ga5.approval.id'], approval['approvalId'])
        self.assertEqual(attrs(gate_spans[0])['ga5.receipt.nonce'], nonce)

    def test_12_advanced_redaction_otlp_and_errors(self):
        p, first = self.create()
        p['sensitive']['accessToken'] = 'NEVER_EXPORT_TOKEN_456'
        # Test a separate fresh run with the sensitive canary present before create.
        p['runId'] = 'audit_'+uuid.uuid4().hex
        p['policy']['doNotExport'].append('NEVER_EXPORT_TOKEN_456')
        r = self.client.post('/v2/incidents', json=p)
        self.assertEqual(r.status_code, 200, r.text)
        done = self.complete(p, r.json())
        otlp = json.dumps(done['otlp'])
        for secret in [SECRET, 'NEVER_EXPORT_TOKEN_456', p['incident']['transcript'], 'OFFLINE_FAKE_TOKEN_DO_NOT_EXPORT']:
            self.assertNotIn(secret, otlp)
        for s in spans(done):
            a = attrs(s)
            self.assertNotIn('gen_ai.tool.call.arguments', a)
            self.assertNotIn('gen_ai.tool.call.result', a)
            self.assertNotIn('authorization', a)
            self.assertNotIn('query', a)
            self.assertNotIn('transcript', a)
        # Contract explicitly REQUIRES raw arguments in actionLog, so check
        # secrets are absent there, NOT that legitimate arguments are absent.
        serialized = json.dumps(done)
        self.assertNotIn('NEVER_EXPORT_TOKEN_456', serialized)
        self.assertNotIn(SECRET, serialized)
        self.assertEqual(done['actionLog'][0]['arguments']['service'], 'billing')
        conflict = copy.deepcopy(p)
        conflict['incident']['transcript'] += '\n[ev3] changed'
        err = self.client.post('/v2/incidents', json=conflict)
        self.assertEqual(err.status_code, 409)
        self.assertNotIn('NEVER_EXPORT_TOKEN_456', err.text)
        self.assertNotIn(SECRET, err.text)
        invalid = copy.deepcopy(p)
        invalid['runId'] = 'audit_'+uuid.uuid4().hex
        invalid['profile'] = 'wrong-profile'
        err = self.client.post('/v2/incidents', json=invalid)
        self.assertIn(err.status_code, (400, 422))
        self.assertNotIn('NEVER_EXPORT_TOKEN_456', err.text)
        self.assertNotIn(SECRET, err.text)


    # Additional contract-focused checks. Test numbers correspond to the user's 30-point checklist.
    def test_13_valid_create_and_invalid_payloads(self):
        p, st = self.create()
        self.assertEqual(st['status'], 'waiting')
        for change in ('profile', 'incidentId', 'toolCatalog'):
            q=copy.deepcopy(p); q['runId']='audit_'+uuid.uuid4().hex
            if change=='profile': q['profile']='ga5-incident-agent/v1'
            elif change=='incidentId': del q['incident']['incidentId']
            else: del q['toolCatalog']
            r=self.client.post('/v2/incidents',json=q)
            self.assertIn(r.status_code,(400,422),r.text)
            self.assertEqual(self.client.get('/v2/incidents/'+q['runId']).status_code,404)

    def test_14_sensitive_object_absent_from_actual_model_request(self):
        import asyncio
        from unittest.mock import patch
        from types import SimpleNamespace
        class Response:
            def raise_for_status(self): pass
            def json(self): return {'choices':[{'message':{'content':json.dumps({
                'rootCause':'database_connection_exhaustion','evidence':['ev1','ev2'],
                'diagnostics':[{'toolName':'query_logs','arguments':{'service':'billing','query':'pool timeout','windowMinutes':15},'evidence':['ev1']}],
                'effect':{'toolName':'page_owner','arguments':{'service':'billing','severity':'SEV-1'}}})}}]}
        seen=[]
        class FakeHTTP:
            def __init__(self,**kwargs): pass
            async def __aenter__(self): return self
            async def __aexit__(self,*args): return False
            async def post(self,url,*,headers,json):
                seen.append(copy.deepcopy(json))
                return Response()
        p=payload()
        with patch.object(m.httpx,'AsyncClient',FakeHTTP),patch.dict(os.environ,{'AI_PIPE_TOKEN':'OFFLINE_FAKE_TOKEN_DO_NOT_EXPORT'}):
            diagnosis, diagnostics, effect=asyncio.run(m.__dict__['plan_original'](p,p['incident'],p['toolCatalog'],p['policy']))
        self.assertEqual(len(seen),1)
        serialized=json.dumps(seen)
        self.assertNotIn(SECRET,serialized)
        self.assertNotIn('accessToken',serialized)
        self.assertNotIn('privateNote',serialized)
        self.assertEqual(diagnosis['rootCause'],'database_connection_exhaustion')

    def test_15_model_proposal_rejects_invalid_evidence_and_duplicate_diagnostics(self):
        p=payload(); evidence=m.get_evidence(p['incident']['transcript'])
        proposal={'rootCause':'database_connection_exhaustion','evidence':['ev1','ev2'],
            'diagnostics':[{'toolName':'query_logs','arguments':{'service':'billing','query':'pool timeout','windowMinutes':15},'evidence':['ev1']}],
            'effect':{'toolName':'page_owner','arguments':{'service':'billing','severity':'SEV-1'}}}
        self.assertFalse(m.proposal_errors(proposal,p['incident'],p['toolCatalog'],p['policy'],evidence))
        bad=copy.deepcopy(proposal);bad['evidence']=['ev1','fake']
        self.assertTrue(m.proposal_errors(bad,p['incident'],p['toolCatalog'],p['policy'],evidence))
        bad=copy.deepcopy(proposal);bad['diagnostics']*=2
        self.assertTrue(m.proposal_errors(bad,p['incident'],p['toolCatalog'],p['policy'],evidence))
        bad=copy.deepcopy(proposal);bad['rootCause']='not_allowed'
        self.assertTrue(m.proposal_errors(bad,p['incident'],p['toolCatalog'],p['policy'],evidence))

    @unittest.skip('A mocked model cannot prove real-model prompt-injection resistance; run separately with AI Pipe and known expected diagnosis.')
    def test_16_live_prompt_injection_resistance(self): pass

    def test_17_trace_context_and_fresh_context(self):
        p=payload(); parent='00-'+'1'*32+'-'+'2'*16+'-01'
        r=self.client.post('/v2/incidents',json=p,headers={'traceparent':parent,'tracestate':'vendor=123'})
        self.assertEqual(r.status_code,200,r.text)
        for d in r.json()['dispatches']:
            self.assertEqual(d['traceparent'].split('-')[1],'1'*32)
            self.assertNotEqual(d['traceparent'].split('-')[2],'2'*16)
            self.assertEqual(d['tracestate'],'vendor=123')
        done=self.complete(p,r.json())
        server=next(s for s in spans(done) if s['name']=='POST /v2/incidents')
        self.assertEqual(server['parentSpanId'],'2'*16)
        p2, st2=self.create()
        for d in st2['dispatches']:
            self.assertRegex(d['traceparent'],r'^00-[0-9a-f]{32}-[0-9a-f]{16}-01$')
            self.assertNotIn('tracestate',d)

    def test_18_diagnostic_evidence_unique_and_catalog(self):
        p,st=self.create()
        self.assertLessEqual(len(st['dispatches']),p['policy']['maximumDiagnostics'])
        catalog={t['name'] for t in p['toolCatalog']}
        for d in st['dispatches']:
            self.assertIn(d['toolName'],catalog)
            self.assertNotIn(d['toolName'],p['policy']['effectTools'])
            self.assertTrue(d['evidence'])
            self.assertEqual(len(d['evidence']),len(set(d['evidence'])))
            self.assertTrue(set(d['evidence']).issubset(st['diagnosis']['evidence']))

    def test_19_503_retry_never_more_than_two_attempts(self):
        MODE['diagnostics']=1
        p,st=self.create(); d=st['dispatches'][0]
        r=self.client.post('/v2/incidents/'+p['runId']+'/receipts',json={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d,503,'503')]})
        self.assertEqual(r.status_code,200)
        nxt=r.json(); self.assertEqual(nxt['approvals'],[])
        d2=nxt['dispatches'][0]; self.assertEqual(d2['attempt'],2)
        r=self.client.post('/v2/incidents/'+p['runId']+'/receipts',json={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d2,503,'503')]})
        self.assertEqual(r.status_code,200)
        done=r.json();self.assertEqual(done['status'],'failed')
        self.assertFalse(done.get('dispatches'))
        physical=[s for s in spans(done) if s['name']=='POST tool/query_logs']
        self.assertEqual(len(physical),2)
        self.assertEqual([attrs(s)['http.request.resend_count'] for s in physical],['0','1'])

    def test_20_timeout_without_effect_or_approval(self):
        MODE.update(diagnostics=1,effect='rollback_deployment')
        p,st=self.create();d=st['dispatches'][0]
        r=self.client.post('/v2/incidents/'+p['runId']+'/receipts',json={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d,0,'timeout')]})
        self.assertEqual(r.status_code,200)
        done=r.json();self.assertEqual(done['status'],'failed')
        self.assertFalse(done.get('approvals'))
        self.assertFalse(any(x['phase']=='effect' for x in done['actionLog']))
        self.assertIn('rollback_deployment',done['suppressed'])

    def test_21_recursive_digest_and_approval_reservation(self):
        args={'z':[{'b':2,'a':1}],'a':{'y':2,'x':1}}
        expected='{"a":{"x":1,"y":2},"z":[{"a":1,"b":2}]}'
        self.assertEqual(m.canonical(args),expected)
        self.assertEqual(m.digest(args),hashlib.sha256(expected.encode()).hexdigest())
        MODE['effect']='rollback_deployment'
        p,st=self.create(); gate=receipt(self.client,p['runId'],st['dispatches']).json()
        a=gate['approvals'][0]
        self.assertFalse(gate['dispatches'])
        self.assertRegex(a['argumentsDigest'],r'^[0-9a-f]{64}$')
        self.assertGreaterEqual(len(a['actionId']),8)
        self.assertGreaterEqual(len(a['approvalId']),8)

    def test_22_unapproved_destructive_effect_not_dispatched(self):
        MODE['effect']='rollback_deployment'
        p,st=self.create();gate=receipt(self.client,p['runId'],st['dispatches']).json()
        self.assertEqual(gate['dispatches'],[])
        a=gate['approvals'][0]
        unauthorized={'receiptId':uuid.uuid4().hex,'outcomes':[{'actionId':a['actionId'],'callId':'fake-call-id','attempt':1,'status':200,'nonce':'nonce'}]}
        r=self.client.post('/v2/incidents/'+p['runId']+'/receipts',json=unauthorized)
        self.assertIn(r.status_code,(400,422))
        self.assertEqual(self.client.get('/v2/incidents/'+p['runId']).json(),gate)
        denial={'receiptId':uuid.uuid4().hex,'approvals':[{'approvalId':a['approvalId'],'decision':'denied','nonce':'deny-nonce'}]}
        r=self.client.post('/v2/incidents/'+p['runId']+'/receipts',json=denial)
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['status'],'failed')
        self.assertFalse(any(x['phase']=='effect' for x in r.json()['actionLog']))

    def test_23_terminal_logs_replay_and_zero_model_calls(self):
        p,st=self.create();before=len(CALLS)
        done=self.complete(p,st)
        self.assertTrue(done['actionLog']);self.assertTrue(done['receiptLog'])
        self.assertEqual(self.client.get('/v2/incidents/'+p['runId']).json(),done)
        self.assertEqual(self.client.post('/v2/incidents',json=p).json(),done)
        self.assertEqual(len(CALLS),before)

    def test_24_strict_span_kinds_and_attributes(self):
        p,st=self.create();done=self.complete(p,st)
        ss=spans(done)
        self.assertEqual(len([s for s in ss if s['name']=='POST /v2/incidents' and s['kind']==2]),1)
        self.assertEqual(len([s for s in ss if s['name']=='chat incident-plan' and s['kind']==3]),1)
        chat=next(s for s in ss if s['name']=='chat incident-plan')
        self.assertEqual(attrs(chat)['gen_ai.operation.name'],'chat')
        self.assertTrue(attrs(chat)['gen_ai.request.model'])
        for s in ss:
            a=attrs(s)
            self.assertEqual(a['ga5.run.id'],p['runId'])
            self.assertEqual(a['ga5.public.marker'],p['publicMarker'])
            if s['name'].startswith('execute_tool '):
                self.assertEqual(s['kind'],1)
                for key in ('ga5.action.id','gen_ai.tool.name','gen_ai.tool.call.id','gen_ai.operation.name'):
                    self.assertIn(key,a)
            if s['name'].startswith('POST tool/'):
                self.assertEqual(s['kind'],3)
                for key in ('ga5.action.id','ga5.attempt','ga5.receipt.id','ga5.receipt.nonce','http.request.method','http.request.resend_count','http.response.status_code'):
                    self.assertIn(key,a)
                self.assertEqual(a['http.request.method'],'POST')
                self.assertNotIn('error.type',a)

    def test_25_replay_conflicts_leave_terminal_state_unchanged(self):
        p,st=self.create();done=self.complete(p,st)
        changed=copy.deepcopy(p);changed['incident']['transcript']='[ev1] different\n[ev2] changed'
        self.assertEqual(self.client.post('/v2/incidents',json=changed).status_code,409)
        self.assertEqual(self.client.get('/v2/incidents/'+p['runId']).json(),done)

    @unittest.skip("The grader's private seventh audit incident is unavailable; synthetic tests cannot certify its score.")
    def test_26_hidden_audit_incident(self): pass

    @unittest.skip('Full seven-incident 110-second deadline requires real provider and deployed service; no offline mock can establish it.')
    def test_27_live_full_suite_deadline(self): pass

    def test_28_receipts_get_replays_never_call_model(self):
        p,st=self.create();n=len(CALLS)
        self.client.get('/v2/incidents/'+p['runId'])
        self.client.post('/v2/incidents',json=p)
        d=st['dispatches'][0]; body={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d)]}
        self.client.post('/v2/incidents/'+p['runId']+'/receipts',json=body)
        self.client.post('/v2/incidents/'+p['runId']+'/receipts',json=body)
        self.assertEqual(len(CALLS),n)

    def test_29_no_action_attempt_flagged_in_test_harness(self):
        p=payload();p['runId']='audit_'+uuid.uuid4().hex
        p['incident']['transcript']='No evidence-tagged lines'
        # Real planner would reject insufficient evidence. The mocked planner
        # bypasses that check; directly test the production evidence gate.
        self.assertLess(len(m.get_evidence(p['incident']['transcript'])),2)
        self.assertEqual(self.client.get('/v2/incidents/'+p['runId']).status_code,404)

    def test_30_synthetic_canary_and_trace_redaction(self):
        p,st=self.create();done=self.complete(p,st)
        serialized=json.dumps(done)
        for secret in (SECRET,'OFFLINE_FAKE_TOKEN_DO_NOT_EXPORT',p['incident']['transcript']):
            self.assertNotIn(secret,serialized)
        for s in spans(done):
            a=attrs(s)
            self.assertNotIn('gen_ai.tool.call.arguments',a)
            self.assertNotIn('gen_ai.tool.call.result',a)
            self.assertNotIn('authorization',a)

if __name__=='__main__':
    unittest.main(verbosity=2)
