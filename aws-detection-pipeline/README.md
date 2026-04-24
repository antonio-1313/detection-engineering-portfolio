# Serverless Detection Pipeline — AWS

A cloud-native detection pipeline built on AWS serverless services. The pipeline ingests CloudTrail audit events, evaluates them against detection logic in Lambda, and generates alerts via SNS while persisting findings to DynamoDB. It demonstrates the same core principles as an enterprise SIEM detection rule — event-driven alerting, structured telemetry, and pipeline design — applied to cloud-native infrastructure.

---

## Architecture

```
AWS CloudTrail
     │
     │ (API call events — management plane activity)
     ▼
Amazon EventBridge
     │
     │ (event pattern rules — filter for suspicious API calls)
     ▼
AWS Lambda (Detection Engine)
     │
     ├──► Amazon DynamoDB   (persist findings — queryable alert store)
     └──► Amazon SNS        (alert delivery — email / downstream integration)
```

### Component Breakdown

| Component | Role in the Pipeline |
|-----------|---------------------|
| **CloudTrail** | Telemetry source — logs every AWS API call with caller identity, source IP, timestamp, and request parameters. Equivalent to a Sysmon event log for cloud infrastructure. |
| **EventBridge** | Detection layer 1 — applies event pattern rules to filter the CloudTrail stream. Only events matching a pattern (e.g., specific API calls, specific services) are forwarded to Lambda. This is the equivalent of a log source filter in Sigma. |
| **Lambda** | Detection layer 2 — stateless function that evaluates each event against detection logic. Implements the condition logic equivalent to a Sigma rule's `detection:` block. Enriches findings before writing and alerting. |
| **DynamoDB** | Alert store — persists each finding with TTL. Provides a queryable, time-ordered record of detections. Equivalent to writing an alert to a SIEM's alert index. |
| **SNS** | Alert delivery — sends notifications to configured subscribers (email, SQS, Lambda for further enrichment). Equivalent to a SIEM notification action. |

---

## What It Detects

The pipeline is designed to detect suspicious AWS management plane activity — actions taken against the account's control plane that indicate compromise, reconnaissance, or privilege escalation:

| Detection | CloudTrail API | Why It Matters |
|-----------|---------------|----------------|
| Root account login | `ConsoleLogin` with `userIdentity.type: Root` | Root usage is almost never legitimate in a mature account; any root console login warrants investigation |
| IAM policy attachment | `AttachUserPolicy`, `AttachRolePolicy` | Attackers escalate privilege by attaching `AdministratorAccess` to compromised identities |
| Security control disabled | `DeleteTrail`, `StopLogging`, `DeleteFlowLogs` | Defense evasion — attackers disable logging to prevent detection of subsequent actions |
| New IAM user created | `CreateUser` | Persistence — attackers create backdoor accounts to maintain access after the initial compromise vector is remediated |
| Access key created | `CreateAccessKey` | Credential harvesting — programmatic access keys can be used for long-term persistence outside the console |

---

## Detection Engineering Concepts Demonstrated

**Event-driven alerting:** The pipeline reacts to events as they occur — there is no polling interval or batch window. This mirrors how a SIEM with real-time alerting works: telemetry arrives, a rule evaluates it, an alert fires. The architecture makes the latency explicit and measurable.

**Layered detection logic:** EventBridge handles coarse filtering (which event types matter at all), while Lambda implements the fine-grained condition logic (field-level checks, enrichment, threshold logic). This separation mirrors the Sigma `logsource` → `detection` structure and reflects how mature SIEM pipelines separate ingestion filtering from rule evaluation.

**Structured findings:** Each DynamoDB record is a structured finding — not a raw log. It contains the evaluated fields, the detection name, severity, and timestamp. This mirrors how a SIEM normalizes events into a consistent alert schema (ECS in Elastic, ASIM in Sentinel).

**Cloud-native telemetry:** CloudTrail is the AWS equivalent of Windows Security Event logs — it's the authoritative audit log for the control plane. Understanding which API calls map to which attacker behaviors (the MITRE ATT&CK Cloud matrix) is the cloud analog of mapping Sysmon Event IDs to technique coverage.

**Pipeline observability:** Lambda logs execution metrics to CloudWatch. Failed invocations, processing errors, and latency are all observable — equivalent to monitoring a SIEM rule's execution health.

---

## Threat Model

This pipeline targets the **initial access → privilege escalation → defense evasion** chain in a cloud environment:

1. An attacker obtains AWS credentials via phishing, credential stuffing, or exposed keys in source code
2. They probe the account with read-only API calls (reconnaissance)
3. They escalate privilege by attaching a managed policy to their identity
4. They disable CloudTrail or flow logs to prevent detection of subsequent lateral movement
5. They create a backdoor IAM user or access key for persistence

The pipeline fires at steps 3–5 and provides enough telemetry (source IP, identity ARN, timestamp) to support incident response.

---

## Setup

See the project source for deployment instructions. The infrastructure is defined with the AWS CDK / CloudFormation and can be deployed to any AWS account.

Required IAM permissions for the Lambda execution role:
- `dynamodb:PutItem` on the findings table
- `sns:Publish` on the alert topic
- `cloudtrail:LookupEvents` (for enrichment queries — optional)
