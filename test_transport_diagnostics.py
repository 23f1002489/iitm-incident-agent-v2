"""Offline regression tests for malformed AI Pipe output and replay fingerprints."""
import asyncio, copy, importlib.util, json, os, unittest
from unittest.mock import patch
from pathlib import Path
spec=importlib.util.spec_from_file_location('incident_patch', Path(__file__).with_name('main_transport_diagnostics.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FakeResponse:
    def __init__(self, content): self.content=content
    def raise_for_status(self): pass
    def json(self): return {'choices':[{'message':{'content':self.content}}]}
class FakeClient:
    def __init__(self, responses, calls): self.responses=responses;self.calls=calls
    async def __aenter__(self):return self
    async def __aexit__(self,*a):return False
    async def post(self,url,*,headers,json):
        self.calls.append(copy.deepcopy(json))
        return FakeResponse(self.responses[len(self.calls)-1])
class Tests(unittest.TestCase):
    def test_malformed_json_retries_then_accepts(self):
        incident={'title':'db','service':'svc','severity':'high','transcript':'[e1] pool full\n[e2] timeout','allowedRootCauses':['database_connection_exhaustion']}
        catalog=[{'name':'query_logs','inputSchema':{'type':'object'}},{'name':'page_owner','inputSchema':{'type':'object'}}]
        policy={'maximumDiagnostics':1,'effectTools':['page_owner'],'approvalRequiredFor':[]}
        valid={'rootCause':'database_connection_exhaustion','evidence':['e1','e2'],'diagnostics':[{'toolName':'query_logs','arguments':{},'evidence':['e1']}],'effect':{'toolName':'page_owner','arguments':{}}}
        calls=[]
        with patch.dict(os.environ,{'AI_PIPE_TOKEN':'offline'}),patch.object(m.httpx,'AsyncClient',return_value=FakeClient(['{invalid',json.dumps(valid)],calls)):
            diagnosis,diagnostics,effect=asyncio.run(m.plan({},incident,catalog,policy))
        self.assertEqual(len(calls),2)
        self.assertEqual(diagnosis['evidence'],['e1','e2'])
        self.assertIn('not a valid JSON proposal',calls[1]['messages'][-1]['content'])
    def test_extra_fields_are_preserved_for_conflict_hash(self):
        payload={'profile':'ga5-incident-agent/v2','runId':'same','agentName':'incident-response','publicMarker':'marker','incident':{'incidentId':'id','title':'db','service':'svc','severity':'high','transcript':'[e1] x\n[e2] y','allowedRootCauses':['database_connection_exhaustion']},'toolCatalog':[{'name':'query_logs','description':'x','inputSchema':{'type':'object'}}],'policy':{'maximumDiagnostics':1,'effectTools':['page_owner'],'approvalRequiredFor':[]}}
        a=m.CreateIncidentInput.model_validate(payload).model_dump()
        changed=copy.deepcopy(payload);changed['policy']['newConstraint']='different'
        b=m.CreateIncidentInput.model_validate(changed).model_dump()
        self.assertNotEqual(m.digest(a),m.digest(b))
        changed=copy.deepcopy(payload);changed['toolCatalog'][0]['newField']='different'
        c=m.CreateIncidentInput.model_validate(changed).model_dump()
        self.assertNotEqual(m.digest(a),m.digest(c))
if __name__=='__main__':unittest.main(verbosity=2)
