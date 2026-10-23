"""PostgreSQL integration tests for main_patched.py; no AI Pipe calls.
Run from directory containing main_patched.py with DATABASE_URL set.
Creates isolated run IDs; deletes only those rows on completion.
"""
import asyncio
import copy
import importlib.util
import json
import os
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(override=True)

url = os.environ.get('DATABASE_URL', '')
if not url.startswith(('postgresql://', 'postgresql+psycopg://', 'postgres://')):
    raise SystemExit('Set DATABASE_URL to a PostgreSQL URL (not SQLite).')
os.environ['AI_PIPE_TOKEN'] = 'offline-mocked'
import app.main as m

print("TESTING APPLICATION:", m.__file__)

# path = Path(__file__).with_name('main_patched.py')
# if not path.exists():
#     raise SystemExit('Place main_patched.py beside this script.')
# spec = importlib.util.spec_from_file_location('pg_agent_under_test', path)
# m = importlib.util.module_from_spec(spec)
# sys.modules[spec.name] = m
# spec.loader.exec_module(m)
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

PREFIX = 'pgtest_' + uuid.uuid4().hex[:12]
created = []
planner_calls = []

async def fake_plan(payload, incident, catalog, policy):
    planner_calls.append(payload['runId'])
    return ({'rootCause': 'database_connection_exhaustion', 'evidence': ['ev1', 'ev2']},
            [{'toolName': 'query_logs', 'arguments': {'service': 'svc'}, 'evidence': ['ev1']},
             {'toolName': 'query_metrics', 'arguments': {'service': 'svc'}, 'evidence': ['ev2']}],
            {'toolName': 'page_owner', 'arguments': {'service': 'svc'}})

m.plan = fake_plan

def payload():
    rid = PREFIX + '_' + uuid.uuid4().hex
    created.append(rid)
    return {'profile': 'ga5-incident-agent/v2', 'runId': rid,
            'agentName': 'incident-response', 'publicMarker': 'safe-marker',
            'sensitive': {'accessToken': 'DO_NOT_EXPORT_PG_TEST'},
            'incident': {'incidentId': 'i1', 'title': 'DB issue', 'service': 'svc',
                         'severity': 'SEV-1', 'transcript': '[ev1] pool full\n[ev2] timeouts',
                         'allowedRootCauses': ['database_connection_exhaustion']},
            'toolCatalog': [{'name': name, 'description': name,
                             'inputSchema': {'type': 'object', 'required': ['service'],
                                             'properties': {'service': {'type': 'string'}}}}
                            for name in ['query_logs', 'query_metrics', 'page_owner']],
            'policy': {'maximumDiagnostics': 3, 'effectTools': ['page_owner'],
                       'approvalRequiredFor': []}}

def outcome(d):
    return {'actionId': d['actionId'], 'callId': d['callId'], 'attempt': d['attempt'],
            'status': 200, 'resultClass': 'diagnosis_confirmed', 'nonce': uuid.uuid4().hex}

def post_receipt(c, rid, outcomes, receipt_id=None):
    return c.post(f'/v2/incidents/{rid}/receipts', json={
        'receiptId': receipt_id or uuid.uuid4().hex, 'outcomes': outcomes})

def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print('PASS:', message, flush=True)

def run():
    check(m.engine.dialect.name == 'postgresql', 'real PostgreSQL SQLAlchemy dialect')
    with m.engine.connect() as db:
        check(db.execute(text('SELECT 1')).scalar() == 1, 'Neon database connection')
    with TestClient(m.app) as c:
        p = payload()
        r = c.post('/v2/incidents', json=p)
        check(r.status_code == 200, f'create incident HTTP 200 (got {r.status_code}: {r.text[:180]})')
        first = r.json()
        check(len(first['dispatches']) == 2, 'two parallel diagnostics dispatched')
        with m.Session() as db:
            row = db.get(m.Run, p['runId'])
            check(row is not None and json.loads(row.state_json)['runId'] == p['runId'], 'record persisted in PostgreSQL')
        replay = c.post('/v2/incidents', json=p)
        check(replay.status_code == 200 and replay.json() == first and planner_calls.count(p['runId']) == 1,
              'identical request replay without planner call')
        changed = copy.deepcopy(p)
        changed['publicMarker'] = 'changed'
        check(c.post('/v2/incidents', json=changed).status_code == 409, 'changed run content HTTP 409')
        d1, d2 = first['dispatches']
        r1body = {'receiptId': uuid.uuid4().hex, 'outcomes': [outcome(d1)]}
        r1 = c.post(f'/v2/incidents/{p["runId"]}/receipts', json=r1body)
        check(r1.status_code == 200 and r1.json()['status'] == 'waiting', 'first partial receipt keeps run waiting')
        check(c.post(f'/v2/incidents/{p["runId"]}/receipts', json=r1body).json() == r1.json(), 'identical receipt replay')
        bad = copy.deepcopy(r1body)
        bad['outcomes'][0]['nonce'] = uuid.uuid4().hex
        check(c.post(f'/v2/incidents/{p["runId"]}/receipts', json=bad).status_code == 409,
              'changed receipt content HTTP 409')
        r2 = post_receipt(c, p['runId'], [outcome(d2)])
        check(r2.status_code == 200 and len(r2.json()['dispatches']) == 1 and
              r2.json()['dispatches'][0]['phase'] == 'effect', 'effect dispatched after all diagnostics')
        effect = r2.json()['dispatches'][0]
        # rf = post_receipt(c, p['runId'], [outcome(effect)])
        # check(rf.status_code == 200 and rf.json()['status'] == 'completed', 'terminal result saved')
        # check(c.get(f'/v2/incidents/{p["runId"]}').json() == rf.json(), 'GET returns persisted terminal result')
        # check('DO_NOT_EXPORT_PG_TEST' not in json.dumps(rf.json()), 'sensitive token not exported')
        rf = post_receipt(c, p['runId'], [outcome(effect)])

        check(
            rf.status_code == 200 and rf.json()['status'] == 'completed',
            'terminal result saved'
        )

        # Validate OTLP trace from the completed incident.
        from test_otlp import validate_otlp

        check('otlp' in rf.json(), 'terminal response contains OTLP')
        validate_otlp(rf.json()['otlp'], p['runId'])

        check(
            c.get(f'/v2/incidents/{p["runId"]}').json() == rf.json(),
            'GET returns persisted terminal result'
        )

        check(
            'DO_NOT_EXPORT_PG_TEST' not in json.dumps(rf.json()),
            'sensitive token not exported'
        )

        # Simulate application restart by using a newly constructed SQLAlchemy engine/session.
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        fresh_engine = create_engine(m.DB_URL, pool_pre_ping=True)
        try:
            with Session(fresh_engine) as fresh:
                row = fresh.get(m.Run, p['runId'])
                check(row is not None and json.loads(row.state_json)['status'] == 'completed',
                      'fresh database connection reads persisted final state')
        finally:
            fresh_engine.dispose()

        # Concurrency probe: intentionally detect races rather than pretend they are fixed.
        p2 = payload()
        barrier = threading.Barrier(2)
        def simultaneous_create(_):
            with TestClient(m.app) as worker:
                barrier.wait(timeout=10)
                try:
                    res = worker.post('/v2/incidents', json=p2)
                    return ('http', res.status_code)
                except Exception as exc:
                    return ('exception', type(exc).__name__)
        with ThreadPoolExecutor(max_workers=2) as pool:
            create_results = list(pool.map(simultaneous_create, range(2)))
        print('OBSERVE concurrent create:', create_results)
        with m.Session() as db:
            check(db.query(m.Run).filter(m.Run.run_id == p2['runId']).count() == 1,
                  'PostgreSQL primary key prevents duplicate run rows')
        if any(kind == 'exception' or status not in (200, 409) for kind, status in create_results):
            print('RACE DETECTED: concurrent create produced an unhandled exception or unexpected HTTP status')
        else:
            print('Concurrent create responses were controlled; repeat to assess stability')

        p3 = payload()
        first3 = c.post('/v2/incidents', json=p3).json()
        e1, e2 = first3['dispatches']
        barrier2 = threading.Barrier(2)
        def simultaneous_receipt(d):
            with TestClient(m.app) as worker:
                barrier2.wait(timeout=10)
                try:
                    res = post_receipt(worker, p3['runId'], [outcome(d)])
                    return ('http', res.status_code)
                except Exception as exc:
                    return ('exception', type(exc).__name__)
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipt_results = list(pool.map(simultaneous_receipt, [e1, e2]))
        print('OBSERVE concurrent receipts:', receipt_results)
        state = c.get(f'/v2/incidents/{p3["runId"]}').json()
        with m.Session() as db:
            stored = json.loads(db.get(m.Run, p3['runId']).state_json)
        print('OBSERVE receipt state:', {'receiptLogCount': len(stored['receiptLog']),
              'pendingCount': len(stored['pending']), 'status': stored['status']})
        pending = list(stored["pending"].values())

        if (
            len(stored["receiptLog"]) == 2 and len(pending) == 1  and pending[0]["dispatch"]["phase"] == "effect"
            and stored["stage"] == "effect"
        ):
            print("PASS: concurrent receipts processed correctly")
        else:
            print("FAIL: concurrent receipt state is incorrect")
        # if len(stored['receiptLog']) != 2 or stored['pending']:
        #     print('RACE DETECTED: lost receipt update or stale pending action')
        # else:
        #     print('Concurrent receipts retained both outcomes in this run; repeat to assess stability')
    
    # Lifecycle test: retry exactly once after HTTP 503.
    p_retry = payload()
    initial = c.post("/v2/incidents", json=p_retry)
    check(initial.status_code == 200, "retry scenario created")

    d1, d2 = initial.json()["dispatches"]

    failed = outcome(d1)
    failed["status"] = 503

    retry_response = post_receipt(
        c, p_retry["runId"], [failed]
    )
    check(retry_response.status_code == 200, "503 receipt accepted")

    retries = retry_response.json()["dispatches"]
    check(
        len(retries) == 1
        and retries[0]["actionId"] == d1["actionId"]
        and retries[0]["callId"] == d1["callId"]
        and retries[0]["attempt"] == 2,
        "503 creates exactly one correlated retry"
    )

    second_failure = outcome(retries[0])
    second_failure["status"] = 503

    exhausted = post_receipt(
        c, p_retry["runId"], [second_failure]
    )
    check(
        exhausted.status_code == 200
        and not exhausted.json()["dispatches"],
        "second 503 does not create a third attempt"
    )

    # Complete the other diagnostic. The effect must be suppressed.
    other = post_receipt(
        c, p_retry["runId"], [outcome(d2)]
    )
    check(
        other.status_code == 200
        and other.json()["status"] == "failed"
        and other.json()["chosenEffect"] in other.json()["suppressed"]
        and not any(
            action["phase"] == "effect"
            for action in other.json()["actionLog"]
        ),
        "exhausted diagnostic retry suppresses effect"
    )

    # Lifecycle test: diagnostic timeout.
    p_timeout = payload()
    created_timeout = c.post("/v2/incidents", json=p_timeout)
    check(created_timeout.status_code == 200, "timeout scenario created")

    t1, t2 = created_timeout.json()["dispatches"]

    timed_out = outcome(t1)
    timed_out["status"] = 0

    timeout_response = post_receipt(
        c, p_timeout["runId"], [timed_out]
    )
    check(
        timeout_response.status_code == 200,
        "timeout receipt accepted"
    )

    timeout_final = post_receipt(
        c, p_timeout["runId"], [outcome(t2)]
    )
    check(
        timeout_final.status_code == 200
        and timeout_final.json()["status"] == "failed"
        and timeout_final.json()["chosenEffect"] in timeout_final.json()["suppressed"]
        and not any(
            action["phase"] == "effect"
            for action in timeout_final.json()["actionLog"]
        ),
        "diagnostic timeout suppresses effect"
    )
    
    # Traceparent propagation test.
    p_trace = payload()

    incoming_trace_id = "a" * 32
    incoming_parent_id = "b" * 16
    incoming_traceparent = (
        f"00-{incoming_trace_id}-{incoming_parent_id}-01"
    )

    trace_response = c.post(
        "/v2/incidents",
        json=p_trace,
        headers={"traceparent": incoming_traceparent}
    )

    check(
        trace_response.status_code == 200,
        "incoming traceparent accepted"
    )

    trace_dispatches = trace_response.json()["dispatches"]

    check(
        len(trace_dispatches) == 2
        and all(
            d["traceparent"].split("-")[1] == incoming_trace_id
            for d in trace_dispatches
        ),
        "outgoing diagnostic dispatches preserve trace ID"
    )

    # Complete both diagnostics and the effect.
    trace_d1, trace_d2 = trace_dispatches

    trace_next = post_receipt(
        c,
        p_trace["runId"],
        [outcome(trace_d1), outcome(trace_d2)]
    )

    check(
        trace_next.status_code == 200,
        "trace scenario diagnostics completed"
    )

    trace_effect = trace_next.json()["dispatches"][0]

    trace_final = post_receipt(
        c,
        p_trace["runId"],
        [outcome(trace_effect)]
    )

    check(
        trace_final.status_code == 200
        and trace_final.json()["status"] == "completed",
        "trace scenario completed"
    )

    spans = trace_final.json()["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]

    server_spans = [
        s for s in spans
        if s["name"] == "POST /v2/incidents"
    ]

    check(
        len(server_spans) == 1
        and server_spans[0]["traceId"] == incoming_trace_id
        and server_spans[0]["parentSpanId"] == incoming_parent_id,
        "server span preserves incoming trace and parent"
    )

    check(
        all(s["traceId"] == incoming_trace_id for s in spans),
        "all exported spans preserve incoming trace ID"
    )


    # Approval workflow: effect must wait for authorization.
    p_approval = payload()
    p_approval["policy"]["approvalRequiredFor"] = ["page_owner"]

    approval_start = c.post("/v2/incidents", json=p_approval)
    check(approval_start.status_code == 200, "approval scenario created")

    ad1, ad2 = approval_start.json()["dispatches"]

    approval_wait = post_receipt(
        c,
        p_approval["runId"],
        [outcome(ad1), outcome(ad2)]
    )

    check(
        approval_wait.status_code == 200
        and approval_wait.json()["status"] == "waiting"
        and len(approval_wait.json()["approvals"]) == 1
        and not approval_wait.json()["dispatches"],
        "effect waits for approval without dispatch"
    )

    approval = approval_wait.json()["approvals"][0]

    check(
        approval["toolName"] == "page_owner"
        and bool(approval["approvalId"])
        and bool(approval["argumentsDigest"]),
        "approval request identifies the protected effect"
    )

    print("APPROVAL REQUEST:", approval)


    # Approval granted: dispatch the protected effect.
    approval_nonce = uuid.uuid4().hex
    approval_body = {
        "receiptId": uuid.uuid4().hex,
        "approvals": [{
            "approvalId": approval["approvalId"],
            "decision": "approved",
            "nonce": approval_nonce
        }]
    }

    granted = c.post(
        f'/v2/incidents/{p_approval["runId"]}/receipts',
        json=approval_body
    )

    check(
        granted.status_code == 200
        and granted.json()["status"] == "waiting"
        and len(granted.json()["dispatches"]) == 1,
        "approved decision dispatches one effect"
    )

    approved_effect = granted.json()["dispatches"][0]

    check(
        approved_effect["toolName"] == "page_owner"
        and approved_effect["phase"] == "effect"
        and approved_effect["actionId"] == approval["actionId"]
        and approved_effect["approvalId"] == approval["approvalId"]
        and approved_effect["approvalNonce"] == approval_nonce,
        "effect dispatch carries approval authorization"
    )

    # Identical receipt must replay the original response.
    replay = c.post(
        f'/v2/incidents/{p_approval["runId"]}/receipts',
        json=approval_body
    )

    check(
        replay.status_code == 200
        and replay.json() == granted.json(),
        "identical approval receipt replays safely"
    )

    # Complete the authorized effect.
    approval_complete = post_receipt(
        c,
        p_approval["runId"],
        [outcome(approved_effect)]
    )

    check(
        approval_complete.status_code == 200
        and approval_complete.json()["status"] == "completed",
        "approved effect completes successfully"
    )


    # Approval denied: effect must never be dispatched.
    p_denied = payload()
    p_denied["policy"]["approvalRequiredFor"] = ["page_owner"]

    denied_start = c.post("/v2/incidents", json=p_denied)
    check(denied_start.status_code == 200, "denial scenario created")

    dd1, dd2 = denied_start.json()["dispatches"]

    denied_wait = post_receipt(
        c,
        p_denied["runId"],
        [outcome(dd1), outcome(dd2)]
    )

    check(
        denied_wait.status_code == 200
        and len(denied_wait.json()["approvals"]) == 1,
        "denial scenario requests approval"
    )

    denied_approval = denied_wait.json()["approvals"][0]

    denied_body = {
        "receiptId": uuid.uuid4().hex,
        "approvals": [{
            "approvalId": denied_approval["approvalId"],
            "decision": "denied",
            "nonce": uuid.uuid4().hex
        }]
    }

    denied_final = c.post(
        f'/v2/incidents/{p_denied["runId"]}/receipts',
        json=denied_body
    )

    check(
        denied_final.status_code == 200
        and denied_final.json()["status"] == "failed"
        and "page_owner" in denied_final.json()["suppressed"],
        "denied approval suppresses protected effect"
    )

    check(
        not any(
            a["phase"] == "effect"
            for a in denied_final.json()["actionLog"]
        ),
        "denied effect was never dispatched"
    )

    denied_replay = c.post(
        f'/v2/incidents/{p_denied["runId"]}/receipts',
        json=denied_body
    )

    check(
        denied_replay.status_code == 200
        and denied_replay.json() == denied_final.json(),
        "identical denied approval receipt replays safely"
    )

    print('\nCompleted. Concurrency observations are diagnostic; they are not proof of race safety.')

try:
    run()
finally:
    # Remove only the test-owned run IDs. Do not drop tables or touch other rows.
    try:
        with m.Session.begin() as db:
            db.query(m.Run).filter(m.Run.run_id.in_(created)).delete(synchronize_session=False)
        print('Cleanup: deleted', len(created), 'test run IDs')
    except Exception as exc:
        print('WARNING: cleanup failed; test IDs:', created, 'error:', type(exc).__name__)
