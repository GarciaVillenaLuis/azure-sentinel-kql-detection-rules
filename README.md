# Microsoft Sentinel KQL Threat Detection & Cloud Hunting Rulepack 🛡️🔍

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/azure-sentinel-kql-detection-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/azure-sentinel-kql-detection-rules/actions/workflows/ci.yml)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=flat-square&logo=microsoft-azure&logoColor=white)](https://azure.microsoft.com/services/microsoft-sentinel/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20Cloud-red?style=flat-square&logo=target&logoColor=white)](https://attack.mitre.org/matrices/enterprise/cloud/)
[![Query Language](https://img.shields.io/badge/Language-KQL%20(Kusto)-008272?style=flat-square)](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Rulepack Status](https://img.shields.io/badge/Rulepack-v2.1.0%20Production-success?style=flat-square)](https://github.com/GarciaVillenaLuis/azure-sentinel-kql-detection-rules)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)

Production-grade **Microsoft Sentinel KQL (Kusto Query Language)** analytics rules, automated detection engineering linter, and simulated cloud threat hunting engine mapped against the **MITRE ATT&CK Cloud Matrix** across Azure AD / Entra ID, Microsoft Azure, and Amazon Web Services.

Developed and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Detection Scope & Threat Scenarios

- **Azure AD / Entra ID Password Spray & Credential Stuffing (`SEC-AZ-001`)**:
  - Maps to MITRE **T1110.003** (Password Spraying) and **T1078** (Valid Accounts).
  - Correlates burst authentication failures across multiple tenant users within sliding time windows to eliminate false positives from individual user lockouts.
- **Azure RBAC Privilege Escalation (`SEC-AZ-002`)**:
  - Maps to MITRE **T1098** (Account Manipulation) and **T1078.004** (Cloud Accounts).
  - Detects unauthorized grants of high-privilege roles (Owner, User Access Administrator, Contributor) at Management Group, Subscription, or Resource Group scope.
- **AWS CloudTrail Defense Evasion (`SEC-AWS-001`)**:
  - Maps to MITRE **T1562.001** (Impair Defenses: Disable Cloud Logging).
  - Detects malicious execution of `StopLogging`, `DeleteTrail`, or event selector modification in multi-cloud federated environments.
- **Key Vault Mass Secret Exfiltration (`SEC-AZ-003`)**:
  - Maps to MITRE **T1555** (Credentials from Password Stores) and **T1567** (Exfiltration Over Web Service).
  - Flags abnormal volumetric reads of cryptographic keys and connection strings from Azure Key Vault diagnostic streams.

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Zero third-party pip dependencies required)

### Syntax & Available Options

```bash
python sentinel_kql_engine.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--list-rules` | `flag` | List all registered production detection rules with MITRE mappings |
| `--validate, -v PATH` | `string` | Lint and validate syntax/best-practices of a `.kql` query file |
| `--simulate, -s ID` | `string` | Simulate rule execution against cloud log telemetry (e.g. `SEC-AZ-001`) |
| `--logs, -l PATH` | `string` | Custom path to JSON cloud log events |
| `--stats` | `flag` | Display live detection engineering telemetry and SOC coverage metrics |
| `--format FMT` | `choice` | Output format: `table` (default) or `json` |

---

## 💻 Practical Usage Scenarios

### 1. Catalog All Detection Rules and MITRE Mappings
```bash
python sentinel_kql_engine.py --list-rules
```
**Sample Output:**
```text
--------------------------------------------------------------------------------------------
RULE ID      | SEVERITY   | TABLE            | NAME                                          
--------------------------------------------------------------------------------------------
SEC-AZ-001   | HIGH       | SigninLogs       | Azure AD Password Spray and Brute Force Detection
SEC-AZ-002   | CRITICAL   | AzureActivity    | Suspicious Azure RBAC Role Assignment (Privilege Escalation)
SEC-AWS-001  | CRITICAL   | AWSCloudTrail    | AWS CloudTrail Defense Evasion (StopLogging / DeleteTrail)
SEC-AZ-003   | HIGH       | AzureDiagnostics | Anomalous Mass Secret Download from Azure Key Vault
--------------------------------------------------------------------------------------------
```

### 2. Lint and Validate KQL Syntax
```bash
python sentinel_kql_engine.py --validate rules/azure_ad_bruteforce_detection.kql
```
**Sample Output:**
```text
KQL Query Lint Status: [VALID] (15 active lines, 6 pipes)
```

### 3. Simulate Detection on Ingested Cloud Logs
```bash
python sentinel_kql_engine.py --simulate SEC-AZ-001
```
**Sample Output:**
```text
Simulation Result for [SEC-AZ-001] Azure AD Password Spray and Brute Force Detection:
  Severity: HIGH
  Alerts Generated: 1
  -> ALERT: Target [attacker.target@enterprise.com] | Technique: T1110.003 - Password Spraying
```

---

## 🧪 Automated Testing

Execute the test suite locally:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
