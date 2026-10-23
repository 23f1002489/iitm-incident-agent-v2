"""Offline end-to-end contract smoke tests; no AI Pipe or Neon credentials needed."""
import os, sys, uuid, importlib.util
from pathlib import Path
os.environ['DATABASE_URL']='sqlite:////mnt/data/incident_integration.db'
os.environ['AI_PIPE_TOKEN']='offline-mocked'
spec=importlib.util.spec_from_file_location('incident_under_test',Path(__file__).with_name('main_patched.py'))
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
from fastapi.testclient import TestClient
calls=[]
async def fake_plan(payload,incident,catalog,policy):
    calls.append(payload['runId'])
    return ({'rootCause':'database_connection_exhaustion','evidence':['ev1','ev2']},
            [{'toolName':'query_logs','arguments':{'service':'svc'},'evidence':['ev1']},
             {'toolName':'query_metrics','arguments':{'service':'svc'},'evidence':['ev2']}],
            {'toolName':'rollback_deployment','arguments':{'service':'svc','release':'r1'}})
m.plan=fake_plan

def payload():
 return {'profile':'ga5-incident-agent/v2','runId':uuid.uuid4().hex,'agentName':'incident-response','publicMarker':'public-safe',
 'sensitive':{'accessToken':'PRIVATE_CANARY'},'incident':{'incidentId':'i1','title':'db','service':'svc','severity':'SEV-1','transcript':'[ev1] pool timeout\n[ev2] pool exhausted','allowedRootCauses':['database_connection_exhaustion']},
 'toolCatalog':[{'name':x,'description':x,'inputSchema':{'type':'object','required':['service'],'properties':{'service':{'type':'string'}}}} for x in ['query_logs','query_metrics']]+[{'name':'rollback_deployment','description':'rollback','inputSchema':{'type':'object','required':['service','release'],'properties':{'service':{'type':'string'},'release':{'type':'string'}}}}],
 'policy':{'maximumDiagnostics':3,'effectTools':['rollback_deployment'],'approvalRequiredFor':['rollback_deployment']}}
def receipt(client,run,items,key='outcomes',rid=None):
 return client.post(f'/v2/incidents/{run}/receipts',json={'receiptId':rid or uuid.uuid4().hex,key:items})
def outcome(d,status=200):
 return {'actionId':d['actionId'],'callId':d['callId'],'attempt':d['attempt'],'status':status,'resultClass':'diagnosis_confirmed','nonce':uuid.uuid4().hex}
with TestClient(m.app) as c:
 p=payload();r=c.post('/v2/incidents',json=p);assert r.status_code==200,r.text
 first=r.json();assert len(first['dispatches'])==2
 assert c.post('/v2/incidents',json=p).json()==first and len(calls)==1
 changed={**p,'publicMarker':'changed'};assert c.post('/v2/incidents',json=changed).status_code==409
 d1,d2=first['dispatches'];r=receipt(c,p['runId'],[outcome(d1)]);assert r.status_code==200,r.text
 assert r.json()['status']=='waiting' and not r.json()['approvals'] and not r.json()['dispatches'], 'Partial receipts must not advance'
 retry_payload={'receiptId':uuid.uuid4().hex,'outcomes':[outcome(d2,503)]}
 r=c.post(f'/v2/incidents/{p["runId"]}/receipts',json=retry_payload);assert r.status_code==200,r.text
 retry=r.json()['dispatches'][0];assert retry['attempt']==2 and retry['actionId']==d2['actionId'] and retry['callId']==d2['callId'] and retry['traceparent']!=d2['traceparent']
 assert c.post(f'/v2/incidents/{p["runId"]}/receipts',json=retry_payload).json()==r.json()
 changed_receipt={**retry_payload,'outcomes':[dict(retry_payload['outcomes'][0],nonce='different')]}
 assert c.post(f'/v2/incidents/{p["runId"]}/receipts',json=changed_receipt).status_code==409
 r=receipt(c,p['runId'],[outcome(retry)]);assert r.status_code==200,r.text
 approval=r.json()['approvals'][0];assert not r.json()['dispatches']
 r=receipt(c,p['runId'],[{'approvalId':approval['approvalId'],'decision':'approved','nonce':'approval-nonce'}],key='approvals');assert r.status_code==200,r.text
 effect=r.json()['dispatches'][0];assert effect['actionId']==approval['actionId'] and effect['approvalNonce']=='approval-nonce'
 r=receipt(c,p['runId'],[outcome(effect)]);assert r.status_code==200,r.text
 final=r.json();assert final['status']=='completed' and len(final['actionLog'])==4 and len(final['receiptLog'])==5
 assert c.get(f'/v2/incidents/{p["runId"]}').json()==final
 assert 'PRIVATE_CANARY' not in str(final)
 spans=final['otlp']['resourceSpans'][0]['scopeSpans'][0]['spans'];ids=[x['spanId'] for x in spans];assert len(ids)==len(set(ids))
 assert sum(x['name']=='incident.join' for x in spans)==1
 assert sum(x['name']=='approval_gate' for x in spans)==1
 assert sum(x['name']=='chat incident-plan' for x in spans)==1
 for d in final['actionLog']:
  sid=d['traceparent'].split('-')[2];assert sid in ids
 print('PASS: creation, replay, 409 conflicts, partial receipts, 503 retry, approval, effect, persistence, OTLP basic topology, redaction')
 p2=payload();r=c.post('/v2/incidents',json=p2);assert r.status_code==200
 ds=r.json()['dispatches'];r=receipt(c,p2['runId'],[outcome(ds[0],0)|{'errorType':'timeout'},outcome(ds[1])]);assert r.status_code==200,r.text
 assert r.json()['status']=='failed' and not r.json().get('dispatches') and r.json()['suppressed']==['rollback_deployment']
 print('PASS: timeout suppresses dependent effect')
