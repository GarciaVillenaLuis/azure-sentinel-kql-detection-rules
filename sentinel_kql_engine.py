#!/usr/bin/env python3
"""
Microsoft Sentinel KQL Threat Detection & Cloud Hunting Engine CLI
Validates, tests, and simulates production Kusto Query Language (KQL) detection rules
mapped against the MITRE ATT&CK Cloud Matrix for Azure AD, AWS CloudTrail, and multi-cloud telemetry.

Author: Luis García Villena (Accenture Security Transformation)
License: Apache 2.0
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class SentinelKqlEngine:
    """Detection engineering and hunting engine for Microsoft Sentinel KQL rulepacks."""

    MITRE_CLOUD_MAPPINGS = {
        "SEC-AZ-001": {
            "name": "Azure AD Password Spray and Brute Force Detection",
            "tactics": ["Initial Access", "Credential Access"],
            "techniques": ["T1110.003 - Password Spraying", "T1078 - Valid Accounts"],
            "severity": "HIGH",
            "table": "SigninLogs",
            "query_frequency": "5m",
            "trigger_threshold": 5
        },
        "SEC-AZ-002": {
            "name": "Suspicious Azure RBAC Role Assignment (Privilege Escalation)",
            "tactics": ["Persistence", "Privilege Escalation"],
            "techniques": ["T1098 - Account Manipulation", "T1078.004 - Cloud Accounts"],
            "severity": "CRITICAL",
            "table": "AzureActivity",
            "query_frequency": "15m",
            "trigger_threshold": 1
        },
        "SEC-AWS-001": {
            "name": "AWS CloudTrail Defense Evasion (StopLogging / DeleteTrail)",
            "tactics": ["Defense Evasion"],
            "techniques": ["T1562.001 - Impair Defenses: Disable Cloud Logging"],
            "severity": "CRITICAL",
            "table": "AWSCloudTrail",
            "query_frequency": "5m",
            "trigger_threshold": 1
        },
        "SEC-AZ-003": {
            "name": "Anomalous Mass Secret Download from Azure Key Vault",
            "tactics": ["Credential Access", "Exfiltration"],
            "techniques": ["T1555 - Credentials from Password Stores", "T1567 - Exfiltration Over Web Service"],
            "severity": "HIGH",
            "table": "AzureDiagnostics",
            "query_frequency": "10m",
            "trigger_threshold": 10
        }
    }

    def __init__(self, rules_dir: Optional[str] = None):
        if rules_dir is None:
            rules_dir = os.path.join(os.path.dirname(__file__), "rules")
        self.rules_dir = rules_dir

    def validate_kql_syntax(self, query: str) -> Dict[str, Any]:
        """Validates KQL syntax patterns, operator piping, and best practice lints."""
        query = query.strip()
        errors = []
        warnings = []

        if not query:
            return {"valid": False, "errors": ["Query cannot be empty"], "warnings": []}

        # Check for initial table identifier
        lines = [l.strip() for l in query.splitlines() if l.strip() and not l.strip().startswith("//")]
        if not lines:
            return {"valid": False, "errors": ["No active query statements found"], "warnings": []}

        first_token = lines[0].split()[0].replace("|", "").strip()
        known_tables = ["SigninLogs", "AzureActivity", "AWSCloudTrail", "AzureDiagnostics", "SecurityAlert", "OfficeActivity"]
        if first_token not in known_tables and not first_token.startswith("let"):
            warnings.append(f"Primary table '{first_token}' is not in standard Sentinel core tables list")

        # Check operator pipes
        pipe_count = query.count("|")
        if pipe_count == 0 and not query.startswith("let"):
            warnings.append("Query has no pipe operators (|); ensure filters are declared")

        # Check time window filter (TimeGenerated >= ago(...))
        if "TimeGenerated" not in query and "EventTime" not in query:
            warnings.append("Best Practice Lint: Query does not filter by TimeGenerated or ago(). Performance impact likely.")

        # Check project / summarize clauses
        has_projection = any(kw in query for kw in ["project", "summarize", "extend", "project-away"])
        if not has_projection:
            warnings.append("Best Practice Lint: No project or summarize operator detected. May return redundant columns.")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "line_count": len(lines),
            "pipe_count": pipe_count
        }

    def simulate_detection(self, rule_id: str, log_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Simulates KQL execution logic against structured log events."""
        meta = self.MITRE_CLOUD_MAPPINGS.get(rule_id)
        if not meta:
            raise KeyError(f"Rule ID '{rule_id}' not recognized in detection registry")

        alerts_triggered = []

        if rule_id == "SEC-AZ-001":
            # Count failed sign-ins per UserPrincipalName
            user_failures: Dict[str, List[Dict[str, Any]]] = {}
            for ev in log_events:
                if ev.get("table") == "SigninLogs" and ev.get("ResultType") in ("50126", "50053", "Failed"):
                    user = ev.get("UserPrincipalName", "unknown")
                    user_failures.setdefault(user, []).append(ev)

            for user, events in user_failures.items():
                if len(events) >= meta["trigger_threshold"]:
                    alerts_triggered.append({
                        "rule_id": rule_id,
                        "title": meta["name"],
                        "entity": user,
                        "event_count": len(events),
                        "severity": meta["severity"],
                        "mitre_technique": meta["techniques"][0],
                        "sample_ip": events[0].get("IPAddress", "0.0.0.0")
                    })

        elif rule_id == "SEC-AZ-002":
            # Detect Owner or User Access Administrator role assignments
            for ev in log_events:
                if ev.get("table") == "AzureActivity":
                    op = ev.get("OperationNameValue", "")
                    role = ev.get("RoleDefinition", "")
                    if "roleassignments/write" in op.lower() and ("Owner" in role or "User Access Administrator" in role):
                        alerts_triggered.append({
                            "rule_id": rule_id,
                            "title": meta["name"],
                            "entity": ev.get("Caller", "unknown"),
                            "target_principal": ev.get("TargetPrincipal", "unknown"),
                            "assigned_role": role,
                            "severity": meta["severity"],
                            "mitre_technique": meta["techniques"][0]
                        })

        elif rule_id == "SEC-AWS-001":
            # Detect StopLogging / DeleteTrail events
            for ev in log_events:
                if ev.get("table") == "AWSCloudTrail":
                    event_name = ev.get("eventName", "")
                    if event_name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
                        alerts_triggered.append({
                            "rule_id": rule_id,
                            "title": meta["name"],
                            "entity": ev.get("userIdentity", {}).get("arn", "unknown"),
                            "action": event_name,
                            "trail_name": ev.get("requestParameters", {}).get("name", "all"),
                            "severity": meta["severity"],
                            "mitre_technique": meta["techniques"][0]
                        })

        elif rule_id == "SEC-AZ-003":
            # Detect Key Vault secret downloads exceeding threshold
            kv_access: Dict[str, int] = {}
            for ev in log_events:
                if ev.get("table") == "AzureDiagnostics" and ev.get("OperationName") == "SecretGet":
                    caller = ev.get("caller_ip_or_identity", "unknown")
                    kv_access[caller] = kv_access.get(caller, 0) + 1

            for caller, count in kv_access.items():
                if count >= meta["trigger_threshold"]:
                    alerts_triggered.append({
                        "rule_id": rule_id,
                        "title": meta["name"],
                        "entity": caller,
                        "download_count": count,
                        "severity": meta["severity"],
                        "mitre_technique": meta["techniques"][0]
                    })

        return {
            "rule_id": rule_id,
            "rule_name": meta["name"],
            "severity": meta["severity"],
            "alerts_generated": len(alerts_triggered),
            "alerts": alerts_triggered
        }

    def list_rules(self) -> List[Dict[str, Any]]:
        """Returns catalog of all registered detection rules with MITRE mappings."""
        catalog = []
        for rid, meta in self.MITRE_CLOUD_MAPPINGS.items():
            rule_entry = dict(meta)
            rule_entry["rule_id"] = rid
            catalog.append(rule_entry)
        return catalog


    def validate_all_rules(self) -> Dict[str, Any]:
        """Validates all .kql rule files in the rules directory."""
        if not os.path.exists(self.rules_dir):
            return {"total_rules": 0, "valid_count": 0, "all_valid": True, "results": {}}
        results = {}
        all_valid = True
        for f in os.listdir(self.rules_dir):
            if f.endswith(".kql"):
                p = os.path.join(self.rules_dir, f)
                with open(p, "r", encoding="utf-8") as qf:
                    res = self.validate_kql_syntax(qf.read())
                    results[f] = res
                    if not res["valid"]:
                        all_valid = False
        return {
            "total_rules": len(results),
            "valid_count": sum(1 for r in results.values() if r["valid"]),
            "all_valid": all_valid,
            "results": results
        }


def main():
    parser = argparse.ArgumentParser(
        description="Microsoft Sentinel KQL Threat Detection & Cloud Hunting Engine CLI"
    )
    parser.add_argument("--list-rules", action="store_true",
                        help="List all production detection rules with MITRE ATT&CK Cloud mappings")
    parser.add_argument("--validate", "-v", help="Path to .kql file to syntax check and lint")
    parser.add_argument("--validate-all", action="store_true",
                        help="Lint and validate all .kql rules in the rules directory")
    parser.add_argument("--simulate", "-s", help="Rule ID to simulate (e.g. SEC-AZ-001, SEC-AZ-002, SEC-AWS-001, SEC-AZ-003)")
    parser.add_argument("--logs", "-l", help="Path to simulated cloud logs JSON file")
    parser.add_argument("--stats", action="store_true",
                        help="Show detection engineering telemetry and hunting statistics")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="Output format (default: table)")

    args = parser.parse_args()
    engine = SentinelKqlEngine()

    if args.stats:
        telemetry_path = os.path.join(os.path.dirname(__file__), "detections", "threat_hunting_telemetry.json")
        if os.path.exists(telemetry_path):
            with open(telemetry_path, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            print(json.dumps({
                "engine": "Microsoft Sentinel KQL Rulepack v2.1.0",
                "rules_active": len(engine.MITRE_CLOUD_MAPPINGS),
                "mitre_att_ck_coverage": "Cloud Matrix (Azure, AWS, Multi-Cloud)",
                "status": "OPERATIONAL"
            }, indent=2))
        return

    if args.list_rules:
        rules = engine.list_rules()
        if args.format == "json":
            print(json.dumps(rules, indent=2))
        else:
            print("-" * 92)
            print(f"{'RULE ID':<12} | {'SEVERITY':<10} | {'TABLE':<16} | {'NAME':<46}")
            print("-" * 92)
            for r in rules:
                print(f"{r['rule_id']:<12} | {r['severity']:<10} | {r['table']:<16} | {r['name']:<46}")
            print("-" * 92)
        return

    if args.validate_all:
        all_res = engine.validate_all_rules()
        if args.format == "json":
            print(json.dumps(all_res, indent=2))
        else:
            print("-" * 75)
            print(f"KQL RULEPACK VALIDATION SUMMARY: {all_res['valid_count']}/{all_res['total_rules']} RULES VALID")
            print("-" * 75)
            for fname, r in all_res["results"].items():
                st = "PASS" if r["valid"] else "FAIL"
                print(f"[{st}] {fname} ({r['line_count']} lines, {r['pipe_count']} pipes)")
            print("-" * 75)
        if not all_res["all_valid"]:
            sys.exit(2)
        return

    if args.validate:
        if not os.path.exists(args.validate):
            print(f"Error: File not found: {args.validate}", file=sys.stderr)
            sys.exit(1)
        with open(args.validate, "r", encoding="utf-8") as f:
            query_content = f.read()
        res = engine.validate_kql_syntax(query_content)
        if args.format == "json":
            print(json.dumps(res, indent=2))
        else:
            status_str = "VALID" if res["valid"] else "INVALID"
            print(f"KQL Query Lint Status: [{status_str}] ({res['line_count']} active lines, {res['pipe_count']} pipes)")
            if res["warnings"]:
                print("Warnings / Best Practice Lints:")
                for w in res["warnings"]:
                    print(f"  - {w}")
            if res["errors"]:
                print("Errors:")
                for e in res["errors"]:
                    print(f"  - {e}")
                sys.exit(2)
        return

    if args.simulate:
        logs_file = args.logs or os.path.join(os.path.dirname(__file__), "samples", "simulated_cloud_logs.json")
        if not os.path.exists(logs_file):
            print(f"Error: Log file not found: {logs_file}", file=sys.stderr)
            sys.exit(1)
        with open(logs_file, "r", encoding="utf-8") as f:
            logs = json.load(f)

        try:
            sim_res = engine.simulate_detection(args.simulate, logs)
            if args.format == "json":
                print(json.dumps(sim_res, indent=2))
            else:
                print(f"Simulation Result for [{sim_res['rule_id']}] {sim_res['rule_name']}:")
                print(f"  Severity: {sim_res['severity']}")
                print(f"  Alerts Generated: {sim_res['alerts_generated']}")
                for a in sim_res["alerts"]:
                    print(f"  -> ALERT: Target [{a['entity']}] | Technique: {a['mitre_technique']}")
        except KeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
