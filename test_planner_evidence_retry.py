"""Focused, offline test for the evidence-ID corrective retry in app.main.plan.
Run from the project root: python test_planner_evidence_retry.py
"""
import asyncio
import copy
import json
import os
import unittest
from unittest.mock import patch

import app.main as m


class FakeResponse:
    def __init__(self, proposal):
        self.proposal = proposal

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": json.dumps(self.proposal)}}]}


class FakeAIClient:
    def __init__(self, proposals, requests):
        self.proposals = proposals
        self.requests = requests

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, *, headers, json):
        self.requests.append(copy.deepcopy(json))
        index = len(self.requests) - 1
        if index >= len(self.proposals):
            raise AssertionError("Unexpected extra AI Pipe request")
        return FakeResponse(self.proposals[index])


class EvidenceRetryTest(unittest.TestCase):
    def test_invalid_evidence_then_valid_evidence(self):
        incident = {
            "title": "DB pool saturation",
            "service": "orders-api",
            "severity": "high",
            "transcript": (
                "[ev1] Database connection pool is exhausted.\n"
                "[ev2] Pool acquisition requests are timing out.\n"
                "[ev3] CPU utilization remains normal."
            ),
            "allowedRootCauses": ["database_connection_exhaustion"],
        }
        catalog = [
            {"name": "query_logs", "inputSchema": {
                "type": "object", "properties": {"service": {"type": "string"}},
                "required": ["service"], "additionalProperties": False,
            }},
            {"name": "page_owner", "inputSchema": {
                "type": "object", "properties": {"service": {"type": "string"}},
                "required": ["service"], "additionalProperties": False,
            }},
        ]
        policy = {
            "maximumDiagnostics": 1,
            "effectTools": ["page_owner"],
            "approvalRequiredFor": [],
        }
        valid = {
            "rootCause": "database_connection_exhaustion",
            "evidence": ["ev1", "ev2"],
            "diagnostics": [{"toolName": "query_logs", "arguments": {
                "service": "orders-api"}, "evidence": ["ev1"]}],
            "effect": {"toolName": "page_owner", "arguments": {"service": "orders-api"}},
        }
        invalid = copy.deepcopy(valid)
        invalid["evidence"] = ["ev1", "ev999"]
        requests = []
        fake = FakeAIClient([invalid, valid], requests)
        with patch.dict(os.environ, {"AI_PIPE_TOKEN": "offline-test-token"}), \
             patch.object(m.httpx, "AsyncClient", return_value=fake):
            diagnosis, diagnostics, effect = asyncio.run(
                m.plan({"sensitive": {"secret": "must-not-send"}}, incident, catalog, policy)
            )

        self.assertEqual(len(requests), 2, "Planner must make exactly two attempts")
        self.assertEqual(diagnosis, {
            "rootCause": "database_connection_exhaustion", "evidence": ["ev1", "ev2"]
        })
        self.assertEqual(diagnostics, valid["diagnostics"])
        self.assertEqual(effect, valid["effect"])
        messages = requests[1]["messages"]
        self.assertEqual(len(messages), 4, "Second request must include correction dialogue")
        self.assertIn("ev999", messages[2]["content"])
        self.assertIn("allowed evidence", messages[3]["content"].lower())
        self.assertNotIn("must-not-send", json.dumps(requests))
        print("PASS: first invalid evidence ID triggers one corrective retry")
        print("PASS: second valid proposal accepted with exact diagnosis and tool arguments")
        print("PASS: corrective feedback included; sensitive data not forwarded")
        print("PASS: no real AI Pipe calls or tokens consumed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
