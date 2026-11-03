#!/usr/bin/env python3
"""
Unit tests for Microsoft Sentinel KQL Threat Detection Engine CLI
Author: Luis García Villena
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sentinel_kql_engine import SentinelKqlEngine


class TestSentinelKqlEngine(unittest.TestCase):

    def setUp(self):
        self.engine = SentinelKqlEngine()

    def test_list_rules(self):
        rules = self.engine.list_rules()
        self.assertGreaterEqual(len(rules), 3)
        rule_ids = [r["rule_id"] for r in rules]
        self.assertIn("SEC-AZ-001", rule_ids)
        self.assertIn("SEC-AZ-002", rule_ids)
        self.assertIn("SEC-AWS-001", rule_ids)

    def test_kql_syntax_valid(self):
        query = """
        SigninLogs
        | where TimeGenerated >= ago(1h)
        | summarize count() by UserPrincipalName
        | project UserPrincipalName, count_
        """
        res = self.engine.validate_kql_syntax(query)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["errors"]), 0)
        self.assertGreater(res["pipe_count"], 0)

    def test_kql_syntax_empty(self):
        res = self.engine.validate_kql_syntax("   ")
        self.assertFalse(res["valid"])
        self.assertIn("Query cannot be empty", res["errors"])

    def test_simulate_azure_ad_password_spray(self):
        logs = [
            {"table": "SigninLogs", "ResultType": "50126", "UserPrincipalName": "victim@domain.com"}
            for _ in range(6)
        ]
        res = self.engine.simulate_detection("SEC-AZ-001", logs)
        self.assertEqual(res["alerts_generated"], 1)
        self.assertEqual(res["alerts"][0]["entity"], "victim@domain.com")

    def test_simulate_azure_rbac_escalation(self):
        logs = [{
            "table": "AzureActivity",
            "OperationNameValue": "microsoft.authorization/roleassignments/write",
            "RoleDefinition": "Owner (Subscription)",
            "Caller": "malicious_user"
        }]
        res = self.engine.simulate_detection("SEC-AZ-002", logs)
        self.assertEqual(res["alerts_generated"], 1)
        self.assertEqual(res["alerts"][0]["assigned_role"], "Owner (Subscription)")

    def test_simulate_aws_cloudtrail_stop_logging(self):
        logs = [{
            "table": "AWSCloudTrail",
            "eventName": "StopLogging",
            "userIdentity": {"arn": "arn:aws:iam::111:user/attacker"}
        }]
        res = self.engine.simulate_detection("SEC-AWS-001", logs)
        self.assertEqual(res["alerts_generated"], 1)
        self.assertEqual(res["alerts"][0]["action"], "StopLogging")


if __name__ == "__main__":
    unittest.main()
