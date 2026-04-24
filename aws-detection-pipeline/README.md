# Serverless Detection Pipeline — AWS

A cloud-native SIEM detection pipeline built on AWS serverless services. The pipeline ingests CloudTrail audit events in real time, evaluates them against detection logic in Lambda, fires alerts via SNS, and persists findings to both DynamoDB and S3. The S3 layer was added specifically to support data analysis and visualization — events are written as structured JSON objects so they can be queried with pandas and visualized with matplotlib without needing a managed BI tool.

---

## Architecture

```
AWS CloudTrail
     │
     │  All management-plane API calls
     ▼
Amazon EventBridge  ←── siem-detection-rule (event pattern filter)
     │
     │  Only monitored event names pass through
     ▼
AWS Lambda  (lambda_handler.py — detection engine)
     │
     ├──► Amazon DynamoDB    SIEM-logs table       (alert store, 24h TTL)
     ├──► Amazon DynamoDB    SIEM-failed-logins    (stateful brute-force counter, 5m TTL)
     ├──► Amazon S3          siem-quicksight-data  (structured event log for analysis)
     └──► Amazon SNS         siem-alerts           (alert delivery — email + filtering)
```

---

## Repository Layout

```
aws-detection-pipeline/
├── lambda/
│   └── lambda_handler.py        # Detection engine — all rule logic lives here
├── eventbridge/
│   └── siem-detection-rule.json # EventBridge event pattern — the ingestion filter
└── analysis/
    └── visuals.ipynb            # Jupyter notebook — 6 visualizations over S3 event data
```

---

## Component Breakdown

### EventBridge Rule — `eventbridge/siem-detection-rule.json`

The EventBridge rule is the first layer of filtering. It watches the CloudTrail event stream and forwards only the specific API calls this pipeline is built to detect. Everything else is dropped before it ever reaches Lambda.

**Sources monitored:** `aws.signin`, `aws.iam`, `aws.ec2`, `aws.s3`

**Events captured:**

| Event | Service | Why It's Monitored |
|-------|---------|-------------------|
| `ConsoleLogin` | signin | Successful and failed console access — T1078 |
| `CreateAccessKey` | IAM | Programmatic credential creation — T1078 |
| `AttachUserPolicy` / `AttachRolePolicy` | IAM | Privilege escalation via policy attachment — T1078 |
| `StopInstances` / `TerminateInstances` | EC2 | Destructive compute actions — T1485 |
| `DeleteVolume` | EC2 | Storage destruction — T1485 |
| `DeleteSecurityGroup` | EC2 | Defense evasion / network control removal |
| `CreateBucket` | S3 | New storage resources — T1537 |
| `DeleteBucket` | S3 | Data destruction — T1485 |
| `PutBucketPolicy` / `DeleteBucketPolicy` | S3 | Exfiltration risk via policy misconfiguration — T1530 |

This is the Sigma `logsource` equivalent in cloud-native form — scope the input before evaluating conditions.

---

### Lambda Function — `lambda/lambda_handler.py`

The Lambda function is the detection engine. It receives each filtered CloudTrail event from EventBridge, extracts the relevant fields, and routes to a handler function based on the event name. Each handler implements the detection logic for that event type — severity classification, field extraction, and alert construction.

**Detection handlers:**

**Root account activity** — any action by a `Root` identity type fires a CRITICAL alert and short-circuits all other logic. Root usage is almost never legitimate in a mature account.

**`CreateAccessKey`** — HIGH severity. Extracts both the actor (who created the key) and the target (who the key was created for) — these can differ if an admin is creating keys on behalf of another user, which is itself a signal worth reviewing.

**`AttachUserPolicy` / `AttachRolePolicy`** — HIGH or CRITICAL depending on whether the policy ARN contains "Admin". An `AdministratorAccess` attachment is an immediate privilege escalation indicator.

**`StopInstances` / `TerminateInstances`** — HIGH/CRITICAL. Extracts the list of affected instance IDs from the request parameters so the alert contains actionable scope.

**`ConsoleLogin` (failure)** — stateful brute-force detection using DynamoDB. Failed logins increment a counter with a 5-minute TTL. When the counter hits 5, a HIGH alert fires and the counter resets. This implements T1110 (Brute Force) detection without any external state management.

**`ConsoleLogin` (success)** — LOW severity. Logged to provide a baseline of normal access that can be correlated against other events.

**`CreateBucket`** — MEDIUM. Extracts bucket name and region.

**`DeleteBucket`** — checks the actor against an approved-user allowlist (`APPROVED_S3_DELETE_USERS`). Unapproved deletions fire CRITICAL immediately. Approved deletions still fire CRITICAL but with a different message — bucket deletion is always high-impact regardless of who does it.

**`PutBucketPolicy`** — parses the bucket policy JSON to check for public (`Principal: *`) grants. Public access grants escalate severity from HIGH to CRITICAL automatically.

**`DeleteBucketPolicy`** — HIGH. Removing a policy may leave the bucket protected only by ACLs, which is a common misconfiguration vector.

**Alert structure:**

Every alert written to SNS includes:
- `alert_id` — unique ID for deduplication
- `event` / `user` / `sourceIP` / `severity` / `timestamp`
- `mitre` — MITRE ATT&CK tag (e.g., `T1110 - Brute Force`)
- `recommended_action` — responder-facing triage guidance, not just a severity label
- `investigate` — direct CloudTrail console link pre-filtered to the actor's username

SNS `MessageAttributes` are set on each publish so subscribers can filter by `severity` or `team` without processing every message.

**Dual persistence — why S3 was added:**

Lambda writes each finding to two places: DynamoDB (`SIEM-logs`) for queryable alert storage with a 24-hour TTL, and S3 (`siem-quicksight-data/events/`) as structured JSON for analysis. The S3 layer was added because DynamoDB's scan API is not suited for aggregation queries — visualizing trends across all users and event types requires loading the full dataset. S3 + pandas handles that without any additional infrastructure or cost.

---

### Analysis Notebook — `analysis/visuals.ipynb`

A Jupyter notebook that reads all event records from the S3 bucket and produces six visualizations against the real pipeline data.

**Data source:** Paginates `siem-quicksight-data/events/` via the S3 API, loads each JSON object, and builds a pandas DataFrame with columns: `username`, `event_name`, `source_ip`, `severity`, `team`, `timestamp`.

**Visualizations:**

| # | Chart | What It Shows |
|---|-------|--------------|
| 1 | Events over time | Daily event volume timeline — identifies activity spikes and quiet periods |
| 2 | Event type distribution | Bar chart of event names by frequency — shows which API calls are most active |
| 3 | Severity breakdown | Pie chart of CRITICAL / HIGH / MEDIUM / LOW distribution — overall risk posture at a glance |
| 4 | Most active users | Bar chart of event count per username — surfaces high-activity accounts for review |
| 5 | Source IP activity | Horizontal bar of events per source IP — anomaly signal for unexpected origins |
| 6 | High & Critical events only | Filtered view of HIGH and CRITICAL event types — analyst focus view |

All charts use a dark theme (`#0f1117` background) consistent with a SOC dashboard aesthetic.

---

## MITRE ATT&CK Coverage

| Technique | ID | Events Covered |
|-----------|----|---------------|
| Valid Accounts | T1078 | ConsoleLogin, CreateAccessKey, AttachUserPolicy, AttachRolePolicy |
| Brute Force | T1110 | ConsoleLogin (repeated failures — stateful 5-minute window counter) |
| Data Destruction | T1485 | TerminateInstances, StopInstances, DeleteBucket, DeleteVolume |
| Data from Cloud Storage | T1530 | PutBucketPolicy, DeleteBucketPolicy |
| Transfer Data to Cloud Account | T1537 | CreateBucket |

---

## Design Decisions

**Why stateful brute-force detection in DynamoDB instead of a fixed-window CloudWatch metric?**
CloudWatch metrics aggregate at the account level. DynamoDB tracks the counter per-username across invocations — a user failing 4 times across 4 separate Lambda executions within 5 minutes still triggers the alert. The TTL attribute handles automatic expiry without a cleanup job.

**Why write to S3 in addition to DynamoDB?**
DynamoDB is optimized for key-based access, not aggregation. Analyzing event trends across all users and event types requires scanning the full dataset, which is expensive with DynamoDB. Writing structured JSON to S3 gives the same data in a form that's analytically flexible — pandas can load it directly for visualization with no additional infrastructure.

**Why include `recommended_action` in the alert payload?**
A severity label tells you how urgent the alert is. The `recommended_action` field tells the responder what to actually do — which IAM permissions to check, whether to disable a key, what to verify with the user. This reduces triage time and keeps the response consistent across team members.

---

## Required IAM Permissions (Lambda Execution Role)

```
dynamodb:PutItem        — SIEM-logs table
dynamodb:UpdateItem     — SIEM-failed-logins table
s3:PutObject            — siem-quicksight-data bucket
sns:Publish             — siem-alerts topic
```
