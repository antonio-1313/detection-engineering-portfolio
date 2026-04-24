# Blog Draft — Building a Serverless Detection Pipeline on AWS

> **Draft notes:** This is a working outline based on the project slides and build. Fill in the bracketed sections with your own voice and specific details. The structure follows a classic engineering post: problem → design → build → failures → fixes → reflection.

---

## Working Title Options
- "Building a Cloud SIEM from Scratch with AWS Lambda and EventBridge"
- "What I Learned Building a Real-Time Detection Pipeline on AWS"
- "From CloudTrail to Alert: A Serverless Security Monitoring Pipeline"

---

## Intro / Hook

[Start with the problem, not the tech. Something like:]

Most cloud security tutorials show you how to turn on GuardDuty and call it a day. We wanted to understand what actually happens under the hood — how does a detection pipeline route an event, evaluate it, and fire an alert in real time? So we built one from scratch using AWS-native services, no managed threat detection, just CloudTrail, EventBridge, Lambda, DynamoDB, SNS, and some Python.

This is what we built, what broke, and what we'd do differently.

> **All source code for this project is on GitHub:** [detection-engineering-portfolio/aws-detection-pipeline](https://github.com/antonio-1313/detection-engineering-portfolio/tree/main/aws-detection-pipeline)

---

## The Problem Statement

The goal was straightforward: identify and alert on high-risk activity in an AWS account in real time. Specifically:

- Authentication abuse — brute force login attempts, root account usage
- Privilege escalation — IAM policy attachments, unexpected role changes
- Destructive infrastructure actions — EC2 terminations, S3 bucket deletions
- Data exposure risk — public bucket policy changes

[Add a sentence about why this matters in a real org — cloud environments are noisy and most teams don't have visibility into their own control plane.]

---

## Initial Design

The initial proposal mapped cleanly to AWS services:

| Detection Need | AWS Service |
|---------------|------------|
| Audit log source | CloudTrail |
| Real-time event routing | EventBridge |
| Detection logic | Lambda |
| State / alert persistence | DynamoDB |
| Alert delivery | SNS |
| Visualization | QuickSight |

The idea was that CloudTrail would feed everything into EventBridge, an event pattern rule would filter for the API calls we cared about, Lambda would run the detection logic, and QuickSight would give us a dashboard.

[Add a diagram or describe the flow in your own words here.]

---

## Building It

### The EventBridge Rule

The first decision was what to actually watch. Not every CloudTrail event is relevant — the account generates hundreds of API calls per hour from normal operations. The EventBridge rule acts as the intake filter: only the events that match the pattern get forwarded to Lambda, everything else is dropped at the source.

We settled on watching four AWS sources — `aws.signin`, `aws.iam`, `aws.ec2`, `aws.s3` — and twelve specific event names:

[List the events and briefly explain why each one is worth watching. You already know this from the Lambda handler — ConsoleLogin for auth, AttachUserPolicy for priv esc, TerminateInstances for destruction, etc.]

This maps to the same concept as a Sigma rule's `logsource` block — you define the scope of what you're ingesting before you write the detection condition.

> 📸 **SCREENSHOT — EventBridge console:** Open EventBridge → Rules → `siem-detection-rule`. Capture the rule detail page showing the event pattern JSON and the Lambda target. This shows the reader exactly what the filter looks like in practice.

### The Lambda Detection Engine

Lambda receives each filtered event and routes it to a handler function based on the event name. Each handler extracts the relevant fields from the CloudTrail detail object and builds an alert.

A few design decisions worth explaining:

**Severity is dynamic, not static.** `AttachUserPolicy` is HIGH by default, but if the policy ARN contains "Admin" it escalates to CRITICAL automatically. `PutBucketPolicy` is HIGH unless the policy grants public access (`Principal: *`), in which case it's CRITICAL. The severity reflects the actual risk of the specific action, not just the event type.

**Every alert includes a `recommended_action` field.** [Explain your reasoning here — a severity label tells you how urgent it is, the recommended action tells the responder what to actually do. This reduces triage time.]

**Every alert includes a direct CloudTrail investigation link** pre-filtered to the actor's username. Small thing, but it removes friction when you're triaging at 2am.

> 📸 **SCREENSHOT — Lambda console:** Open Lambda → Functions → your handler function. Capture the function overview page showing the EventBridge trigger wired up, and optionally a test invocation result showing a formatted alert in the execution logs. This makes the event flow visual.

### Stateful Brute Force Detection

This was one of the more interesting engineering problems. Lambda functions are stateless — every invocation starts cold. So you can't just do `counter += 1` in your function code and expect it to persist across calls.

[Explain the DynamoDB solution here: each failed login increments a counter keyed by username using `update_item` with ADD, a TTL attribute automatically expires the record after 5 minutes, and when the count hits 5 the alert fires and the counter resets. This gives you a sliding window without any scheduled cleanup jobs.]

The trade-off is latency and cost — every failed login now requires a DynamoDB write and read. Under normal conditions this is negligible, but under a real brute force attack hitting Lambda concurrently you could get race conditions on the counter. [Mention how you'd address this in a production system — conditional writes, or moving to an atomic counter service.]

> 📸 **SCREENSHOT — DynamoDB console:** Open DynamoDB → Tables → `SIEM-failed-logins` → Explore items. If you have a test record in there showing a username, fail_count, and ttl field, capture it. This illustrates the stateful counter pattern concretely.

> 📸 **SCREENSHOT — DynamoDB console:** Open DynamoDB → Tables → `SIEM-logs` → Explore items. Capture a few rows showing real alert records — event_name, severity, source_ip, username. This shows findings being persisted as structured data.

### The Approved User Allowlist for S3 Deletes

[Explain the `APPROVED_S3_DELETE_USERS` set. Bucket deletion is always high-impact, but not all deletions are malicious. Rather than suppressing all alerts from admins, you still fire on approved users — but the alert message is different. An unapproved user deleting a bucket fires CRITICAL with a message that explicitly names the unauthorized actor. This is the cloud equivalent of a Sigma filter that excludes known-legitimate parents while still alerting on everything else.]

### SNS Alerts

[Describe what the alert email looks like — the JSON payload with alert_id, severity, mitre tag, recommended_action, and the investigation link.]

> 📸 **SCREENSHOT — SNS alert email:** Show the full alert email received in your inbox from `siem-alerts`. Redact any sensitive account info but keep the alert structure visible — the severity, mitre field, recommended_action, and investigate link are the key things to show. This is the most tangible output of the pipeline.

---

## Issues We Hit

### Issue 1: The Brute Force Alert Never Fired

[Explain that ConsoleLogin failure events weren't showing up in Lambda. Root cause: the EventBridge rule wasn't set up to route failed logins — the `ConsoleLogin` event from `aws.signin` was missing from the rule. Once we added `aws.signin` as a source and confirmed the `ConsoleLogin` detail-type, the events started flowing.]

**Fix:** Added `aws.signin` and `AWS Console Sign In via CloudTrail` as a source and detail-type in the EventBridge rule.

**Lesson:** Test each event type individually before building the handler. EventBridge silently drops events that don't match the rule — there's no "event rejected" log unless you wire up a dead-letter queue.

> 📸 **SCREENSHOT — CloudWatch Logs:** Open CloudWatch → Log groups → your Lambda log group. Show a log stream with the failed login events appearing after the fix. Before/after if you have it. This makes the debugging story real.

### Issue 2: QuickSight S3 Integration Wouldn't Work

[This was the biggest time sink. QuickSight recently overhauled its data source integration UI and the documentation hadn't caught up. Multiple attempts to connect S3 data sources failed with opaque permission errors. The only resolution path was opening a support case with AWS.]

**Fix:** Pivoted to writing event records as structured JSON to S3 and reading them locally with pandas and matplotlib. This actually ended up being more flexible — we could iterate on visualizations without the QuickSight refresh cycle.

**Lesson:** Before committing to a managed visualization service, verify the integration path with a minimal test. QuickSight's S3 integration requires specific bucket policies, manifest files, and IAM role configurations that aren't obvious from the console.

> 📸 **SCREENSHOT — S3 console:** Open S3 → `siem-data` bucket → `events/` prefix. Show the list of JSON files written by Lambda. This illustrates the S3 persistence layer and also shows the pipeline is actively writing data.

### Issue 3: S3 Bucket Permissions Were Locked Down

[Explain the bucket permission setup issue — initial choices meant that changes could only be made through bucket policy updates, which created friction for every subsequent integration attempt, especially the QuickSight work.]

**Fix:** [Describe what you did to work around it or resolve it.]

**Lesson:** Set up S3 bucket permissions with integration flexibility in mind from the start. Overly restrictive policies early in a project compound into obstacles at every subsequent integration point.

---

## Final Architecture

After the fixes and pivots, the final architecture looked like this:

```
CloudTrail → EventBridge (siem-detection-rule) → Lambda
                                                    ├── DynamoDB (SIEM-logs, 24h TTL)
                                                    ├── DynamoDB (SIEM-failed-logins, 5m TTL)
                                                    ├── S3 (siem-data/events/ — structured JSON)
                                                    └── SNS (siem-alerts — severity + team filters)
```

Key changes from the initial design:
- S3 added as a second persistence layer specifically for analysis and visualization
- SNS MessageAttributes added so subscribers can filter by severity and team without processing every message
- QuickSight replaced by a local Python notebook (pandas + matplotlib)

---

## Visualizations

[Describe the six charts briefly and what they're useful for. You can reference the notebook here.]

- Events over time — the timeline view lets you see activity spikes. In our data, [describe what you saw].
- Event type distribution — [what was most frequent?]
- Severity breakdown — [what was the CRITICAL/HIGH ratio?]
- Most active users — [anything interesting here?]
- Source IP activity — [same IPs across multiple events is a signal worth noting]
- High & Critical events only — the analyst focus view

> 📸 **SCREENSHOT — Notebook charts:** Run `visuals.ipynb` and capture each of the six charts. Embed the most visually striking ones inline — the severity pie chart and the events-over-time line chart tend to read best. The source IP horizontal bar is good for showing the anomaly-detection angle.

---

## What I'd Do Differently

**Use GuardDuty.** We learned about it toward the end of the course. It would have replaced a significant chunk of the manual EventBridge + Lambda detection work, given us network-level threat detection that CloudTrail can't provide, and solved the visualization problem through Security Hub. Building the pipeline from scratch was a good learning exercise — but in a real environment, GuardDuty is the right starting point and custom Lambda rules are the supplement, not the foundation.

**Evaluate visualization options before committing.** We assumed QuickSight would be straightforward because it's AWS-native. It wasn't. A 30-minute proof-of-concept connecting S3 to QuickSight before designing the data pipeline would have saved hours of debugging.

**Design for automated response, not just alerting.** The pipeline detects and notifies. A real detection pipeline should also act — disable credentials flagged for brute force, quarantine instances that trigger termination alerts, block logins from unexpected countries. The SNS topic is already there; adding a Lambda subscriber that takes action is the natural next step.

---

## Takeaways

[Write 2-3 sentences in your own voice about what this project gave you as a detection engineer. What do you understand now about cloud-native telemetry, event-driven pipelines, and the detection lifecycle that you didn't understand before?]

---

## Links

- GitHub: [detection-engineering-portfolio/aws-detection-pipeline](https://github.com/antonio-1313/detection-engineering-portfolio/tree/main/aws-detection-pipeline)
- Portfolio: [antonio-lopez.netlify.app](https://antonio-lopez.netlify.app)
