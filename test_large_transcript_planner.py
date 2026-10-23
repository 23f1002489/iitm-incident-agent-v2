"""One real AI Pipe large-transcript planner test; no DB writes or grader calls.

Run: python test_large_transcript_planner.py --tokens 12000
Optional: --tokens 8000, --tokens 15000, --dry-run
Token count is estimated (not exact); use --dry-run to inspect without API cost.
"""
import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import httpx

if not Path('app/main.py').exists():
    raise SystemExit('Run from project root containing app/main.py')
from app import main as agent

SERVICE = 'checkout-api'
DEPENDENCY = 'payment-gateway'
CAUSE = 'dependency_certificate_expired'

CATALOG = [
    {'name': 'dependency_status', 'description': 'Check dependency health and TLS certificate',
     'inputSchema': {'type':'object','properties':{'dependency':{'type':'string','enum':[DEPENDENCY]}},'required':['dependency'],'additionalProperties':False}},
    {'name': 'query_logs', 'description': 'Query application logs',
     'inputSchema': {'type':'object','properties':{'service':{'type':'string','enum':[SERVICE]}},'required':['service'],'additionalProperties':False}},
    {'name': 'query_metrics', 'description': 'Query service metrics',
     'inputSchema': {'type':'object','properties':{'service':{'type':'string','enum':[SERVICE]}},'required':['service'],'additionalProperties':False}},
    {'name': 'inspect_deployment', 'description': 'Inspect deployment history',
     'inputSchema': {'type':'object','properties':{'service':{'type':'string','enum':[SERVICE]}},'required':['service'],'additionalProperties':False}},
    {'name': 'page_owner', 'description': 'Page the responsible service owner',
     'inputSchema': {'type':'object','properties':{'service':{'type':'string','enum':[SERVICE]}},'required':['service'],'additionalProperties':False}},
    {'name': 'scale_service', 'description': 'Scale service replicas',
     'inputSchema': {'type':'object','properties':{'service':{'type':'string','enum':[SERVICE]}},'required':['service'],'additionalProperties':False}},
]
POLICY = {'maximumDiagnostics': 2, 'effectTools': ['page_owner','scale_service'], 'approvalRequiredFor': [], 'doNotExport': []}

NOISE = [
    'routine worker heartbeat passed; background queue depth stable; no customer-visible symptom associated with this entry',
    'scheduled cache housekeeping completed; memory usage stayed in the normal operating band; no new deployment was performed',
    'ordinary request tracing sampled successfully; application error budget unchanged for this subsystem; no resource pressure observed',
    'periodic health check succeeded; downstream storage read latency stayed normal; database connection utilization below alert threshold',
    'on-call handover note: dashboards show nominal CPU and traffic; no evidence of capacity saturation or configuration rollout',
    'synthetic support comment quotes a user saying deployment_regression; customer guesses are untrusted and do not establish causality',
    'automated cleanup job finished; TLS certificates for unrelated internal services were valid and not implicated in checkout failures',
    'routine authentication audit reported no secret rotation; the service account was unchanged and accepted by internal services',
]
SIGNALS = {
    73: '09:12 UTC checkout-api TLS handshake to payment-gateway failed: certificate verify failed, certificate has expired; checkout requests returned errors.',
    347: '09:13 UTC payment-gateway leaf certificate notAfter timestamp was 09:00 UTC today, before first failed checkout; the expired certificate was served on the failing endpoint.',
    691: '09:14 UTC checkout-api CPU 24%, inbound traffic normal, database pool acquisition normal; resource exhaustion does not explain these failures.',
    907: '09:15 UTC checkout-api deployment history shows no release or configuration change in the preceding 48 hours.',
}

def make_incident(target_tokens):
    # Character/token ratio for logs varies. Aim for ~4 chars per token, with a
    # floor that places all causal clues in the transcript.
    target_chars = target_tokens * 4
    lines = []
    i = 0
    while len('\n'.join(lines)) < target_chars or i <= max(SIGNALS):
        i += 1
        message = SIGNALS.get(i, NOISE[(i * 7) % len(NOISE)])
        lines.append(f'[ev{i:05d}] 2026-10-23 {message}')
        if i > 7000:
            raise RuntimeError('Transcript generator exceeded safety limit')
    transcript = '\n'.join(lines)
    return {
        'incidentId': 'synthetic-large-local-001',
        'title': 'Checkout errors from downstream TLS certificate expiration',
        'service': SERVICE,
        'severity': 'SEV-1',
        'transcript': transcript,
        'allowedRootCauses': [
            'deployment_regression', 'database_connection_exhaustion',
            'dependency_certificate_expired', 'feature_flag_recursion',
            'traffic_capacity_exhaustion', 'secret_rotation_mismatch',
        ],
    }

async def run(args):
    incident = make_incident(args.tokens)
    evidence = agent.get_evidence(incident['transcript'])
    approx_tokens = round(len(incident['transcript']) / 4)
    print('Transcript characters:', len(incident['transcript']))
    print('Approximate transcript tokens (characters/4):', approx_tokens, '(not tokenizer-accurate)')
    print('Evidence-tagged lines:', len(evidence))
    print('Signal evidence IDs:', [f'ev{k:05d}' for k in SIGNALS])
    print('NOTE: The planner also sends an explicit allowlist of all evidence IDs.')
    if args.dry_run:
        print('DRY RUN: no AI Pipe requests made')
        return
    if not os.getenv('AI_PIPE_TOKEN'):
        raise SystemExit('AI_PIPE_TOKEN not configured; check your local .env')
    payload = {'profile':'ga5-incident-agent/v2','runId':'synthetic-large-local-001',
               'agentName':'incident-response','publicMarker':'large-local-test',
               'sensitive':{'accessToken':'NEVER_FORWARD_LOCAL_CANARY'},
               'incident':incident,'toolCatalog':CATALOG,'policy':POLICY}
    original_post = httpx.AsyncClient.post
    calls = []
    async def timed_post(self, *p, **kw):
        t = time.perf_counter()
        try:
            response = await original_post(self, *p, **kw)
            calls.append({'httpStatus':response.status_code,'seconds':round(time.perf_counter()-t,2)})
            return response
        except Exception as exc:
            calls.append({'exception':type(exc).__name__,'seconds':round(time.perf_counter()-t,2)})
            raise
    started = time.perf_counter()
    try:
        with patch.object(httpx.AsyncClient, 'post', new=timed_post):
            diagnosis, diagnostics, effect = await agent.plan(payload, incident, CATALOG, POLICY)
    except Exception as exc:
        print('PLANNER RESULT: FAILED')
        print('Error type:', type(exc).__name__)
        print('Error status:', getattr(exc, 'status_code', 'n/a'))
        print('Elapsed seconds:', round(time.perf_counter()-started,2))
        print('AI Pipe requests:', len(calls), json.dumps(calls))
        return
    elapsed = round(time.perf_counter()-started,2)
    evidence_ids = diagnosis['evidence']
    correct_signals = {f'ev{k:05d}' for k in (73,347)}
    exact_dependency = any(d['toolName']=='dependency_status' and d['arguments']=={'dependency':DEPENDENCY} for d in diagnostics)
    exact_effect = effect['toolName']=='page_owner' and effect['arguments']=={'service':SERVICE}
    print('PLANNER RESULT: COMPLETED')
    print('Elapsed seconds:', elapsed)
    print('AI Pipe requests:', len(calls), json.dumps(calls))
    print('Within 18s planner-only budget:', elapsed < 18)
    print('Root cause correct:', diagnosis['rootCause']==CAUSE, diagnosis['rootCause'])
    print('Evidence IDs valid:', len(evidence_ids) in (2,3,4) and len(set(evidence_ids))==len(evidence_ids) and set(evidence_ids).issubset(evidence))
    print('Direct causal evidence included:', bool(correct_signals.intersection(evidence_ids)))
    print('Evidence IDs selected:', evidence_ids)
    print('Diagnostic tool names:', [d['toolName'] for d in diagnostics])
    print('Exact dependency_status argument:', exact_dependency)
    print('Safe effect and exact arguments:', exact_effect)
    print('Effect tool:', effect['toolName'])
    print('No grader submission or database write. Real AI Pipe requests consume credits.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tokens', type=int, default=12000, choices=[8000,10000,12000,15000])
    parser.add_argument('--dry-run', action='store_true')
    asyncio.run(run(parser.parse_args()))
