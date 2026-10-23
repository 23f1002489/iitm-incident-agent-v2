
import json
import re
import uuid

from fastapi.testclient import TestClient
import app.main as m

def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)

def validate_otlp(otlp, expected_run_id):
    resource_spans = otlp["resourceSpans"]
    spans = [
        span
        for resource in resource_spans
        for scope in resource["scopeSpans"]
        for span in scope["spans"]
    ]

    check(len(spans) > 0, "OTLP contains spans")

    trace_ids = {s["traceId"] for s in spans}
    check(len(trace_ids) == 1, "All spans share one trace ID")
    check(
        all(re.fullmatch(r"[0-9a-f]{32}", tid) for tid in trace_ids),
        "Trace IDs have valid format",
    )

    span_ids = [s["spanId"] for s in spans]
    check(len(span_ids) == len(set(span_ids)), "Span IDs are unique")
    check(
        all(re.fullmatch(r"[0-9a-f]{16}", sid) for sid in span_ids),
        "Span IDs have valid format",
    )

    by_id = {s["spanId"]: s for s in spans}
    for s in spans:
        parent = s.get("parentSpanId")
        if parent:
            check(
                parent in by_id,
                f"Parent exists for {s['name']}",
            )

    names = [s["name"] for s in spans]

    check(
        "POST /v2/incidents" in names,
        "Server span exists",
    )
    check(
        any(n.startswith("invoke_agent ") for n in names),
        "Agent span exists",
    )
    check(
        any(n.startswith("chat ") for n in names),
        "Chat span exists",
    )
    check(
        any(n.startswith("execute_tool ") for n in names),
        "Tool execution spans exist",
    )
    check(
        any(n.startswith("POST tool/") for n in names),
        "Physical tool attempt spans exist",
    )
    check(
        "incident.join" in names,
        "Parallel diagnostics join exists",
    )

    joins = [s for s in spans if s["name"] == "incident.join"]
    check(len(joins) == 1, "Exactly one join span")

    check(
        len(joins[0].get("links", [])) == 2,
        "Join links both diagnostics",
    )

    serialized = json.dumps(otlp).lower()
    check(
        "offline-mocked" not in serialized,
        "No mocked API token leaked",
    )

    print("\nOTLP SUMMARY")
    print("Run ID:", expected_run_id)
    print("Trace ID:", next(iter(trace_ids)))
    print("Span count:", len(spans))
    for s in spans:
        print(
            s["name"],
            "| kind:", s["kind"],
            "| parent:", s.get("parentSpanId", "ROOT"),
        )

if __name__ == "__main__":
    run_id = "otlp_" + uuid.uuid4().hex

    # First inspect the application's available test fixtures.
    print("APPLICATION:", m.__file__)
    print("Run ID:", run_id)
    print(
        "This validator expects a completed incident response "
        "containing the 'otlp' field."
    )
    print(
        "Call validate_otlp(response_json['otlp'], run_id) "
        "after completing a run in the existing integration test."
    )
