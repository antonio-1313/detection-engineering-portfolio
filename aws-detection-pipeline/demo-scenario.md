# Demo Scenario — Privilege Escalation to Unauthorized S3 Deletion

This documents the end-to-end attack simulation used to validate the detection pipeline. It demonstrates two chained detections firing in sequence: IAM privilege escalation followed by an unauthorized destructive action.

---

## Scenario Summary

An attacker compromises an admin account and uses it to escalate privileges on a low-privilege user. They then authenticate as that user and delete an S3 bucket. The pipeline detects both actions independently and fires alerts with the correct severity and recommended response.

---

## Setup

| Actor | Account | Starting Permissions |
|-------|---------|---------------------|
| Attacker (using compromised admin) | `admin account` | Full IAM permissions |
| Target / backdoor account | `final-project-user` | No permissions |
| Target resource | Sample S3 bucket | Exists, not empty |

---

## Attack Chain

### Step 1 — Privilege Escalation

Logged into the admin account, attach `AmazonS3FullAccess` to `final-project-user`:

```
IAM → Users → final-project-user → Add permissions → AmazonS3FullAccess
```

> 📸 **SCREENSHOT (video recording):** Capture the IAM console showing the policy attachment action — the user, the policy being attached, and the confirmation screen.

**CloudTrail event generated:** `AttachUserPolicy`

**Alert fired:**

```json
{
  "alert": "Security Event Detected",
  "event": "AttachUserPolicy",
  "severity": "HIGH",
  "mitre": "T1078 - Privilege Escalation",
  "detail": "Policy 'arn:aws:iam::aws:policy/AmazonS3FullAccess' attached to 'final-project-user' by 'admin' — possible privilege escalation",
  "recommended_action": "Confirm the actor is authorized to attach policies. If unexpected, remove the policy and investigate for privilege escalation."
}
```

> 📸 **SCREENSHOT (video recording):** Capture the SNS alert email for the HIGH AttachUserPolicy alert — show the severity, mitre tag, detail, and recommended_action fields.

---

### Step 2 — Unauthorized S3 Bucket Deletion

Sign out of the admin account and authenticate as `final-project-user`. Navigate to S3 and delete the sample bucket.

```
S3 → sample-bucket → Delete bucket → Confirm
```

> 📸 **SCREENSHOT (video recording):** Capture the S3 console showing the bucket deletion confirmation — the bucket name and the success message after deletion.

**CloudTrail event generated:** `DeleteBucket`

**Alert fired:**

```json
{
  "alert": "Security Event Detected",
  "event": "DeleteBucket - Unauthorised User",
  "severity": "CRITICAL",
  "mitre": "T1485 - Data Destruction / Unauthorized Access",
  "detail": "UNAUTHORISED: 'final-project-user' attempted to delete S3 bucket 'sample-bucket'. This user is not in the approved list (AC-admin, al-admin, ZR-admin).",
  "recommended_action": "1. Verify if this deletion was intentional. 2. Revoke 'final-project-user' S3 delete permissions if unauthorised. 3. Restore the bucket from backup or S3 versioning if needed."
}
```

> 📸 **SCREENSHOT (video recording):** Capture the SNS alert email for the CRITICAL DeleteBucket - Unauthorised User alert — this is the key output of the demo, show the full alert payload.

---

## Why This Scenario

The two-step chain tests several things at once:

- **EventBridge routing** — both `AttachUserPolicy` (IAM source) and `DeleteBucket` (S3 source) must be correctly captured and forwarded to Lambda
- **Dynamic severity** — the policy attachment is HIGH; the bucket deletion by a non-approved user escalates to CRITICAL via the allowlist check in `handle_s3_delete_bucket`
- **Allowlist logic** — `final-project-user` is not in `APPROVED_S3_DELETE_USERS`, so the CRITICAL unauthorized-user path fires rather than the standard deletion path
- **Alert quality** — both alerts include the actor identity, source IP, MITRE tag, and actionable recommended response

---

## Detection Chain Diagram

```
Admin attaches S3FullAccess to final-project-user
        │
        ▼
CloudTrail: AttachUserPolicy
        │
        ▼
EventBridge → Lambda → AttachUserPolicy handler
        │
        ▼
SNS alert: HIGH — Privilege Escalation (team: security)
        │
        (attacker switches accounts)
        │
final-project-user deletes sample-bucket
        │
        ▼
CloudTrail: DeleteBucket
        │
        ▼
EventBridge → Lambda → DeleteBucket handler → allowlist check fails
        │
        ▼
SNS alert: CRITICAL — Unauthorised User (team: cloud)
```

---

## Notes

- The brute force detection (T1110) was not demonstrated live due to the 5-minute TTL window on the DynamoDB counter — triggering 5 failures and waiting for the alert within a recording session is impractical. The alert structure was shown statically instead.
- Both alerts were delivered via SNS email within seconds of the CloudTrail events being generated.
- `final-project-user` had no permissions prior to the escalation step — the deletion would not have been possible without the attacker-controlled policy attachment, which is the point of the scenario.
