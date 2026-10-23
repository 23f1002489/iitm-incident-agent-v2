"""Offline tool-schema retry tests. Run: python test_planner_schema_retry.py"""
import asyncio
import copy
import json
import os
import unittest
from unittest.mock import patch
import app.main as m

class FakeResponse:
    def __init__(self, data): self.data = data
    def raise_for_status(self): pass
    def json(self): return {"choices": [{"message": {"content": json.dumps(self.data)}}]}

class FakeClient:
    def __init__(self, proposals, calls): self.proposals, self.calls = proposals, calls
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return False
    async def post(self, url, *, headers, json):
        self.calls.append(copy.deepcopy(json))
        if len(self.calls) > len(self.proposals): raise AssertionError("Unexpected AI request")
        return FakeResponse(self.proposals[len(self.calls)-1])

class ToolSchemaRetryTest(unittest.TestCase):
    def test_invalid_required_type_enum_range_and_extra_then_corrected(self):
        incident = {"title": "DB issue", "service": "orders-api", "severity": "high",
                    "transcript": "[ev1] DB pool exhausted.\n[ev2] Connections timed out.",
                    "allowedRootCauses": ["database_connection_exhaustion"]}
        schema = {"type": "object", "properties": {
            "service": {"type": "string", "enum": ["orders-api"]},
            "metric": {"type": "string", "enum": ["db_pool_wait"]},
            "windowMinutes": {"type": "integer", "minimum": 1, "maximum": 30}},
            "required": ["service", "metric", "windowMinutes"], "additionalProperties": False}
        catalog = [{"name": "query_metrics", "inputSchema": schema},
                   {"name": "page_owner", "inputSchema": {"type": "object", "properties": {
                       "service": {"type": "string", "enum": ["orders-api"]}},
                       "required": ["service"], "additionalProperties": False}}]
        policy = {"maximumDiagnostics": 1, "effectTools": ["page_owner"], "approvalRequiredFor": []}
        valid = {"rootCause": "database_connection_exhaustion", "evidence": ["ev1", "ev2"],
                 "diagnostics": [{"toolName": "query_metrics", "arguments": {
                     "service": "orders-api", "metric": "db_pool_wait", "windowMinutes": 10}, "evidence": ["ev1"]}],
                 "effect": {"toolName": "page_owner", "arguments": {"service": "orders-api"}}}
        bad = copy.deepcopy(valid)
        bad["diagnostics"][0]["arguments"] = {"service": "wrong-service", "windowMinutes": "999", "unexpected": True}
        calls = []
        with patch.dict(os.environ, {"AI_PIPE_TOKEN": "offline-only"}), patch.object(
                m.httpx, "AsyncClient", return_value=FakeClient([bad, valid], calls)):
            diagnosis, diagnostics, effect = asyncio.run(m.plan({"sensitive": {"secret": "HIDDEN_VALUE"}}, incident, catalog, policy))
        self.assertEqual(len(calls), 2)
        self.assertEqual(diagnostics, valid["diagnostics"])
        self.assertEqual(effect, valid["effect"])
        feedback = calls[1]["messages"][-1]["content"]
        self.assertIn("required", feedback)
        self.assertIn("type", feedback)
        self.assertIn("enum", feedback)
        self.assertIn("additionalProperties", feedback)
        self.assertNotIn("HIDDEN_VALUE", json.dumps(calls))
        print("PASS: required/type/enum/additionalProperties failures trigger one corrective retry")
        print("PASS: valid tool arguments accepted; no real AI Pipe requests")

    def test_schema_validator_rejects_out_of_range(self):
        incident = {"allowedRootCauses": ["database_connection_exhaustion"]}
        catalog = [{"name": "query_metrics", "inputSchema": {"type": "object", "properties": {
            "windowMinutes": {"type": "integer", "maximum": 30}}, "required": ["windowMinutes"]}},
            {"name": "page_owner", "inputSchema": {"type": "object"}}]
        policy = {"maximumDiagnostics": 1, "effectTools": ["page_owner"]}
        proposal = {"rootCause": "database_connection_exhaustion", "evidence": ["ev1", "ev2"],
                    "diagnostics": [{"toolName": "query_metrics", "arguments": {"windowMinutes": 999}, "evidence": ["ev1"]}],
                    "effect": {"toolName": "page_owner", "arguments": {}}}
        errs = m.proposal_errors(proposal, incident, catalog, policy, ["ev1", "ev2"])
        self.assertTrue(any("maximum" in e for e in errs), errs)
        print("PASS: numeric maximum constraint enforced")

if __name__ == "__main__": unittest.main(verbosity=2)
