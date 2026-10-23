"""Offline contract audit for Incident Agent v2. No AI Pipe or Neon calls.
Place beside app/main.py; run: python test_seven_category_audit.py
This is a contract regression suite, NOT a hidden-grader replica.
"""
import copy
import importlib.util
import json
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
        cls.client.__exit__(None,None,None)
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

if __name__=='__main__':
    unittest.main(verbosity=2)
