"""End-to-end local tests for IITM incident-agent v2. No real tools are executed.
Run: python test_remaining_v2.py --base-url http://127.0.0.1:8000
Requires: pip install httpx
"""
import argparse
import copy
import json
import re
import sys
import uuid
from collections import Counter

import httpx

RUN_PREFIX = "local-suite"
SECRET = "DO_NOT_EXPORT_SENTINEL_" + uuid.uuid4().hex


def payload(case, destructive=False):
    tools = [
        {"name": "query_metrics", "description": "Read service and database performance metrics", "inputSchema": {
            "type": "object", "properties": {"service": {"type": "string"}, "metric": {"type": "string"}},
            "required": ["service", "metric"]}},
    ]
    if destructive:
        tools.append({"name": "rollback_deployment", "description": "Roll back a service deployment after approval", "inputSchema": {
            "type": "object", "properties": {"service": {"type": "string"}, "deploymentId": {"type": "string"}},
            "required": ["service", "deploymentId"]}})
        effect_tools = ["rollback_deployment"]
        approvals = ["rollback_deployment"]
    else:
        tools.append({"name": "page_owner", "description": "Notify the responsible service owner", "inputSchema": {
            "type": "object", "properties": {"service": {"type": "string"}, "reason": {"type": "string"}},
            "required": ["service", "reason"]}})
        effect_tools = ["page_owner"]
        approvals = []
    return {
        "profile": "ga5-incident-agent/v2", "runId": f"{RUN_PREFIX}-{case}-{uuid.uuid4().hex[:10]}",
        "agentName": "incident-response", "publicMarker": "test-public-marker",
        "sensitive": {"accessToken": SECRET, "privateNote": SECRET},
        "incident": {"incidentId": f"INC-{case}", "title": "Checkout latency after deployment",
            "service": "checkout-api", "severity": "SEV-2",
            "transcript": "[ev_001] Deployment dep-456 was released to checkout-api.\n"
                          "[ev_002] Checkout latency increased immediately after deployment dep-456.\n"
                          "[ev_003] Database query duration increased from 40ms to 1200ms.\n"
                          "[ev_004] CPU and memory are normal.\n"
                          "[ev_005] Query regression is confirmed for checkout-api.",
            "allowedRootCauses": ["slow_database_query", "cpu_saturation", "network_failure"]},
        "toolCatalog": tools,
        "policy": {"maximumDiagnostics": 2, "effectTools": effect_tools,
                   "approvalRequiredFor": approvals, "doNotExport": ["accessToken", "privateNote"]}
    }


class Suite:
    def __init__(self, base_url):
        self.client = httpx.Client(base_url=base_url.rstrip('/'), timeout=25, trust_env=False)
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def check(self, condition, message):
        if not condition:
            raise AssertionError(message)

    def call(self, method, path, data=None, expected=200):
        response = self.client.request(method, path, json=data)
        self.check(response.status_code == expected,
                   f"{method} {path}: expected HTTP {expected}, got {response.status_code}: {response.text[:500]}")
        return response.json()

    def create(self, p):
        result = self.call('POST', '/v2/incidents', p)
        self.check(result['runId'] == p['runId'], 'Wrong runId')
        self.check(result['status'] == 'waiting', 'New run should be waiting')
        self.check(bool(result.get('dispatches')), 'No diagnostic dispatches')
        self.check(all(d['phase'] == 'diagnostic' for d in result['dispatches']), 'Unexpected initial phase')
        return result

    def receipt(self, run_id, dispatches, status=200, result_class='diagnosis_confirmed', error_type=None):
        outcomes = []
        for d in dispatches:
            item = {"actionId": d['actionId'], "callId": d['callId'], "attempt": d['attempt'],
                    "status": status, "resultClass": result_class, "nonce": str(uuid.uuid4())}
            if error_type:
                item['errorType'] = error_type
            outcomes.append(item)
        return {"receiptId": "rcpt-" + uuid.uuid4().hex, "outcomes": outcomes}

    def post_receipt(self, run_id, receipt):
        return self.call('POST', f'/v2/incidents/{run_id}/receipts', receipt)

    def finish_effect(self, run_id, response):
        self.check(response['status'] == 'waiting', 'Expected waiting for effect')
        self.check(len(response['dispatches']) == 1, 'Expected exactly one effect dispatch')
        effect = response['dispatches'][0]
        self.check(effect['phase'] == 'effect', 'Expected effect phase')
        r = self.post_receipt(run_id, self.receipt(run_id, [effect], result_class='effect_completed'))
        self.check(r['status'] == 'completed', 'Effect should complete the run')
        return r

    def test_503_retry(self):
        p = payload('retry')
        first = self.create(p)
        initial = first['dispatches']
        retried = self.post_receipt(p['runId'], self.receipt(p['runId'], initial, status=503, result_class='unavailable'))
        self.check(retried['status'] == 'waiting', '503 should keep run waiting')
        self.check(len(retried['dispatches']) == len(initial), 'Every 503 diagnostic must be retried')
        for before, after in zip(initial, retried['dispatches']):
            self.check(after['attempt'] == 2, 'Retry attempt must be 2')
            self.check(after['actionId'] == before['actionId'], 'Retry changed actionId')
            self.check(after['callId'] == before['callId'], 'Retry changed callId')
            self.check(after['traceparent'] != before['traceparent'], 'Retry must use a new CLIENT span')
        after_diagnostics = self.post_receipt(p['runId'], self.receipt(p['runId'], retried['dispatches']))
        final = self.finish_effect(p['runId'], after_diagnostics)
        self.check(len(final['actionLog']) == 2 * len(initial) + 1, 'Incorrect retry actionLog count')
        self.check(len(final['receiptLog']) == 2 * len(initial) + 1, 'Incorrect retry receiptLog count')
        self.check(any(e['status'] == 503 for e in final['receiptLog']), '503 missing from receiptLog')
        self.validate_otlp(final)

    def test_timeout(self):
        p = payload('timeout')
        first = self.create(p)
        final = self.post_receipt(p['runId'], self.receipt(p['runId'], first['dispatches'], status=0,
                                                          result_class='timeout', error_type='timeout'))
        self.check(final['status'] == 'failed', 'Timeout should fail the run')
        self.check(not final.get('dispatches'), 'No dispatches allowed after timeout failure')
        self.check('page_owner' in final.get('suppressed', []), 'Dependent effect not suppressed')
        self.check(not any(d['phase'] == 'effect' for d in final['actionLog']), 'Effect dispatched after timeout')
        self.validate_otlp(final)
        spans = self.spans(final)
        self.check(any(s.get('kind') == 3 and s['name'].startswith('POST tool/') and
                       s.get('status', {}).get('code') == 2 for s in spans), 'Missing ERROR CLIENT span')

    def test_approval(self, decision):
        p = payload('approval-' + decision, destructive=True)
        first = self.create(p)
        after_diag = self.post_receipt(p['runId'], self.receipt(p['runId'], first['dispatches']))
        self.check(after_diag['status'] == 'waiting', 'Expected approval wait')
        self.check(not after_diag.get('dispatches'), 'Effect dispatched before approval')
        self.check(len(after_diag.get('approvals', [])) == 1, 'Expected one approval request')
        approval = after_diag['approvals'][0]
        self.check(approval['toolName'] == 'rollback_deployment', 'Unexpected approval tool')
        self.check(re.fullmatch('[0-9a-f]{64}', approval['argumentsDigest']) is not None,
                   'Missing SHA-256 argumentsDigest')
        nonce = str(uuid.uuid4())
        receipt = {"receiptId": "approval-" + uuid.uuid4().hex,
                   "approvals": [{"approvalId": approval['approvalId'], "decision": decision, "nonce": nonce}]}
        after_approval = self.post_receipt(p['runId'], receipt)
        if decision == 'approved':
            self.check(after_approval['status'] == 'waiting', 'Approved effect should be pending')
            self.check(len(after_approval.get('dispatches', [])) == 1, 'Expected approved effect dispatch')
            effect = after_approval['dispatches'][0]
            self.check(effect['toolName'] == 'rollback_deployment', 'Wrong effect after approval')
            self.check(effect.get('approvalId') == approval['approvalId'], 'Missing approvalId')
            self.check(effect.get('approvalNonce') == nonce, 'Missing approvalNonce')
            self.check(effect['actionId'] == approval['actionId'], 'Effect actionId differs from reserved approval')
            final = self.finish_effect(p['runId'], after_approval)
        else:
            self.check(after_approval['status'] == 'failed', 'Denied approval should fail the run')
            self.check(not after_approval.get('dispatches'), 'Denied effect was dispatched')
            self.check('rollback_deployment' in after_approval.get('suppressed', []), 'Denied effect not suppressed')
            final = after_approval
        self.validate_otlp(final)
        self.check(any(s['name'] == 'approval_gate' for s in self.spans(final)), 'Missing approval_gate span')

    def test_idempotency(self):
        p = payload('idempotency')
        first = self.create(p)
        self.check(self.call('POST', '/v2/incidents', p) == first, 'Identical create replay changed response')
        changed = copy.deepcopy(p)
        changed['incident']['title'] += ' CHANGED'
        self.call('POST', '/v2/incidents', changed, expected=409)
        receipt = self.receipt(p['runId'], first['dispatches'])
        after = self.post_receipt(p['runId'], receipt)
        self.check(self.post_receipt(p['runId'], receipt) == after, 'Identical receipt replay changed response')
        conflict = copy.deepcopy(receipt)
        conflict['outcomes'][0]['nonce'] = str(uuid.uuid4())
        self.call('POST', f"/v2/incidents/{p['runId']}/receipts", conflict, expected=409)
        final = self.finish_effect(p['runId'], after)
        self.check(self.call('GET', f"/v2/incidents/{p['runId']}") == final,
                   'GET did not return persisted terminal state')
        self.check(self.call('POST', '/v2/incidents', p) == final,
                   'Same create request after completion should return persisted final state')
        self.check(self.post_receipt(p['runId'], receipt) == after,
                   'Receipt replay after completion must return its original cached response')
        self.validate_otlp(final)

    @staticmethod
    def spans(response):
        return [s for resource in response['otlp']['resourceSpans']
                for scope in resource['scopeSpans'] for s in scope['spans']]

    def validate_otlp(self, response):
        spans = self.spans(response)
        self.check(spans, 'No OTLP spans')
        self.check(len([s for s in spans if s['name'] == 'chat incident-plan']) == 1,
                   'Expected exactly one chat incident-plan span')
        self.check(len([s for s in spans if s['name'] == 'POST /v2/incidents' and s['kind'] == 2]) == 1,
                   'Missing SERVER span')
        self.check(len([s for s in spans if s['name'].startswith('invoke_agent ') and s['kind'] == 1]) == 1,
                   'Missing invoke_agent INTERNAL span')
        ids = {s['spanId'] for s in spans}
        self.check(len(ids) == len(spans), 'Duplicate span IDs')
        traces = {s['traceId'] for s in spans}
        self.check(len(traces) == 1, 'Spans have different trace IDs')
        for s in spans:
            self.check(re.fullmatch('[0-9a-f]{32}', s['traceId']) is not None, 'Invalid trace ID')
            self.check(re.fullmatch('[0-9a-f]{16}', s['spanId']) is not None, 'Invalid span ID')
            self.check(s['traceId'] != '0'*32 and s['spanId'] != '0'*16, 'Zero trace/span ID')
            if 'parentSpanId' in s:
                self.check(s['parentSpanId'] in ids, 'Unknown parent span')
            attrs = {a['key']: a['value'] for a in s.get('attributes', [])}
            self.check(attrs.get('ga5.run.id', {}).get('stringValue') == response['runId'],
                       'Missing ga5.run.id attribute')
            self.check(attrs.get('ga5.public.marker', {}).get('stringValue') == 'test-public-marker',
                       'Missing public marker attribute')
        clients = {s['spanId']: s for s in spans if s['kind'] == 3 and s['name'].startswith('POST tool/')}
        self.check(len(clients) == len(response['actionLog']), 'Expected one CLIENT span per physical attempt')
        for action in response['actionLog']:
            match = re.fullmatch(r'00-([0-9a-f]{32})-([0-9a-f]{16})-01', action['traceparent'])
            self.check(match is not None, 'Malformed dispatch traceparent')
            self.check(match[1] in traces and match[2] in clients,
                       'Dispatch traceparent does not match CLIENT span')
        self.check(SECRET not in json.dumps(response), 'Sensitive marker leaked in response or OTLP')
        self.check(not any(key in json.dumps(response['otlp']).lower() for key in ['accesstoken', 'privatenote']),
                   'Sensitive field names leaked in OTLP')

    def run_case(self, label, function):
        print(f'\n[RUN] {label}', flush=True)
        try:
            function()
            self.passed += 1
            print(f'[PASS] {label}', flush=True)
        except Exception as exc:
            self.failed += 1
            print(f'[FAIL] {label}: {type(exc).__name__}: {exc}', flush=True)

    def run_all(self):
        self.run_case('503 retry then success', self.test_503_retry)
        self.run_case('Diagnostic timeout suppresses effect', self.test_timeout)
        self.run_case('Destructive effect approval', lambda: self.test_approval('approved'))
        self.run_case('Destructive effect denial', lambda: self.test_approval('denied'))
        self.run_case('Idempotency, conflicts, GET, and telemetry', self.test_idempotency)
        print(f'\nSUMMARY: {self.passed} passed, {self.failed} failed')
        return self.failed == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    suite = Suite(args.base_url)
    try:
        sys.exit(0 if suite.run_all() else 1)
    finally:
        suite.client.close()
