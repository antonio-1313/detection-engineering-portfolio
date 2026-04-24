import json
import boto3
import time

from util import get_team_from_event

sns_client = boto3.client('sns')
s3_client = boto3.client('s3')
S3_BUCKET = 'siem-quicksight-data'
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
table = dynamodb.Table('SIEM-logs')
failed_logins_table = dynamodb.Table('SIEM-failed-logins')

SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:748464378916:siem-alerts'
FAILED_LOGIN_THRESHOLD = 5
TTL_WINDOW = 300

APPROVED_S3_DELETE_USERS = {'AC-admin', 'al-admin', 'ZR-admin'}


def lambda_handler(event, context):
    print("Event received:")
    print(json.dumps(event, indent=2))

    detail = event.get('detail', {})
    event_name = detail.get('eventName', 'Unknown')
    user_identity = detail.get('userIdentity', {})
    user = user_identity.get('userName',
           user_identity.get('principalId',
           user_identity.get('arn', 'Unknown')))
    source_ip = detail.get('sourceIPAddress', 'Unknown')

    # Root user — always CRITICAL, short-circuit all other logic
    is_root = user_identity.get('type') == 'Root'
    if is_root:
        send_alert(
            event_name=f"{event_name} (ROOT USER)",
            user="ROOT",
            source_ip=source_ip,
            severity='CRITICAL',
            extra="Root account activity detected — immediate investigation required"
        )
        return

    if event_name == 'CreateAccessKey':
        handle_access_key_creation(detail, user, source_ip)

    elif event_name in ['AttachUserPolicy', 'AttachRolePolicy']:
        handle_policy_escalation(detail, user, source_ip, event_name)

    elif event_name in ['StopInstances', 'TerminateInstances']:
        handle_ec2_action(detail, user, source_ip, event_name)

    elif event_name == 'ConsoleLogin':
        event_source = detail.get('eventSource', '')

        if event_source != 'signin.amazonaws.com':
            print(f"Unexpected eventSource for ConsoleLogin: {event_source}, skipping")
            return

        login_result = detail.get('responseElements', {}).get('ConsoleLogin', '')

        if login_result == 'Failure':
            handle_failed_login(user, source_ip)
        else:
            send_alert(event_name, user, source_ip, 'LOW')

    elif event_name == 'CreateBucket':
        handle_s3_create_bucket(detail, user, source_ip)

    elif event_name == 'DeleteBucket':
        handle_s3_delete_bucket(detail, user, source_ip)

    elif event_name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
        handle_s3_bucket_policy(detail, user, source_ip, event_name)

    else:
        send_alert(event_name, user, source_ip, 'MEDIUM')

    return {
        'statusCode': 200,
        'body': 'Detection complete'
    }


def handle_access_key_creation(detail, user, source_ip):
    request_params = detail.get('requestParameters', {}) or {}
    target_user = request_params.get('userName', user)
    extra = f"Access key created for user: {target_user} — possible credential staging"
    send_alert(
        event_name='CreateAccessKey',
        user=user,
        source_ip=source_ip,
        severity='HIGH',
        extra=extra
    )


def handle_policy_escalation(detail, user, source_ip, event_name):
    request_params = detail.get('requestParameters', {}) or {}
    policy_arn = request_params.get('policyArn', 'Unknown policy')
    target_user = request_params.get('userName', '')
    target_role = request_params.get('roleName', '')
    target = target_user or target_role or 'Unknown target'
    severity = 'CRITICAL' if 'Admin' in policy_arn else 'HIGH'
    extra = (
        f"Policy '{policy_arn}' attached to '{target}' "
        f"by '{user}' — possible privilege escalation"
    )
    send_alert(event_name, user, source_ip, severity, extra)


def handle_ec2_action(detail, user, source_ip, event_name):
    request_params = detail.get('requestParameters', {}) or {}
    instances_set = request_params.get('instancesSet', {})
    items = instances_set.get('items', [])
    instance_ids = [i.get('instanceId', 'Unknown') for i in items]
    instance_list = ', '.join(instance_ids) if instance_ids else 'Unknown'
    action = 'terminated' if event_name == 'TerminateInstances' else 'stopped'
    severity = 'CRITICAL' if event_name == 'TerminateInstances' else 'HIGH'
    extra = (
        f"EC2 instance(s) {action}: {instance_list} "
        f"by '{user}' — possible destructive action"
    )
    send_alert(event_name, user, source_ip, severity, extra)


def handle_failed_login(user, source_ip):
    current_time = int(time.time())
    expiry_time = current_time + TTL_WINDOW

    response = failed_logins_table.update_item(
        Key={'username': user},
        UpdateExpression='ADD fail_count :inc SET last_attempt = :ts, #ttl_attr = :ttl',
        ExpressionAttributeNames={'#ttl_attr': 'ttl'},
        ExpressionAttributeValues={
            ':inc': 1,
            ':ts': current_time,
            ':ttl': expiry_time
        },
        ReturnValues='UPDATED_NEW'
    )

    fail_count = int(response['Attributes']['fail_count'])
    print(f"Failed login for {user} — count: {fail_count}")

    if fail_count >= FAILED_LOGIN_THRESHOLD:
        send_alert(
            event_name='ConsoleLogin - Brute Force Detected',
            user=user,
            source_ip=source_ip,
            severity='HIGH',
            extra=f"Failed attempts: {fail_count} in last 5 minutes — MITRE T1110"
        )
        failed_logins_table.update_item(
            Key={'username': user},
            UpdateExpression='SET fail_count = :zero',
            ExpressionAttributeValues={':zero': 0}
        )


def get_bucket_name(detail):
    request_params = detail.get('requestParameters', {}) or {}
    return (
        request_params.get('bucketName') or
        request_params.get('bucket') or
        'Unknown bucket'
    )


def handle_s3_create_bucket(detail, user, source_ip):
    bucket_name = get_bucket_name(detail)
    request_params = detail.get('requestParameters', {}) or {}
    region = (request_params
              .get('createBucketConfiguration', {})
              .get('locationConstraint', 'us-east-1'))
    extra = (
        f"New S3 bucket '{bucket_name}' created by '{user}' "
        f"in region '{region}' from {source_ip} — verify this is authorized"
    )
    send_alert('CreateBucket', user, source_ip, 'MEDIUM', extra)


def handle_s3_delete_bucket(detail, user, source_ip):
    bucket_name = get_bucket_name(detail)

    if user not in APPROVED_S3_DELETE_USERS:
        send_alert(
            event_name='DeleteBucket - Unauthorised User',
            user=user,
            source_ip=source_ip,
            severity='CRITICAL',
            extra=(
                f"UNAUTHORISED: '{user}' attempted to delete S3 bucket "
                f"'{bucket_name}' from {source_ip}. "
                f"This user is not in the approved list "
                f"(AC-admin, al-admin, ZR-admin)."
            )
        )
        return

    extra = (
        f"S3 bucket '{bucket_name}' DELETED by '{user}' from {source_ip} "
        f"— possible data destruction or resource cleanup"
    )
    send_alert('DeleteBucket', user, source_ip, 'CRITICAL', extra)


def handle_s3_bucket_policy(detail, user, source_ip, event_name):
    bucket_name = get_bucket_name(detail)
    request_params = detail.get('requestParameters', {}) or {}

    if event_name == 'PutBucketPolicy':
        policy_raw = request_params.get('bucketPolicy', '')
        is_public = False
        try:
            policy = json.loads(policy_raw)
            for stmt in policy.get('Statement', []):
                principal = stmt.get('Principal', '')
                if principal == '*' or principal == {'AWS': '*'}:
                    is_public = True
                    break
        except Exception:
            pass
        severity = 'CRITICAL' if is_public else 'HIGH'
        public_note = " — WARNING: policy grants PUBLIC access" if is_public else ""
        extra = (
            f"Bucket policy added/updated on '{bucket_name}' "
            f"by '{user}' from {source_ip}{public_note}"
        )
    else:  # DeleteBucketPolicy
        severity = 'HIGH'
        extra = (
            f"Bucket policy DELETED from '{bucket_name}' "
            f"by '{user}' from {source_ip} — bucket may now rely on ACLs only"
        )

    send_alert(event_name, user, source_ip, severity, extra)


def log_event_to_db(event_name, user, source_ip, severity, detail):
    try:
        table.put_item(
            Item={
                'username': user,
                'event_id': f"{int(time.time())}#{event_name}",
                'event_name': event_name,
                'source_ip': source_ip,
                'severity': severity,
                'detail': detail,
                'timestamp': int(time.time()),
                'ttl': int(time.time()) + 86400  # 24-hour TTL
            }
        )
        print(f"Event logged to DynamoDB: {event_name}")
    except Exception as e:
        print(f"DynamoDB log failed: {e}")


def log_event_to_s3(event_name, user, source_ip, severity, detail, team):
    try:
        record = {
            'username': user,
            'event_name': event_name,
            'source_ip': source_ip,
            'severity': severity,
            'detail': detail,
            'team': team,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }
        key = f"events/{int(time.time())}-{event_name}-{user}.json"
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(record),
            ContentType='application/json'
        )
        print(f"Event logged to S3: {key}")
    except Exception as e:
        print(f"S3 log failed: {e}")


def send_alert(event_name, user, source_ip, severity, extra=None):
    timestamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    alert_id = f"SIEM-{int(time.time())}-{user}"

    alert = {
        "alert": "Security Event Detected",
        "alert_id": alert_id,
        "timestamp": timestamp,
        "event": event_name,
        "user": user,
        "sourceIP": source_ip,
        "severity": severity,
        "mitre": get_mitre_tag(event_name),
        "recommended_action": get_recommended_action(event_name, user, source_ip),
        "investigate": (
            f"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home"
            f"?region=us-east-1#/events?Username={user}"
        )
    }

    if extra:
        alert["detail"] = extra

    log_event_to_db(event_name, user, source_ip, severity, extra or '')

    team = get_team_from_event(event_name)
    log_event_to_s3(event_name, user, source_ip, severity, extra or '', team)

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"SIEM Alert [{severity}] - {event_name}",
        Message=json.dumps(alert, indent=2, ensure_ascii=False),
        MessageAttributes={
            "severity": {
                "DataType": "String",
                "StringValue": severity
            },
            "team": {
                "DataType": "String",
                "StringValue": get_team_from_event(event_name) or "general"
            }
        }
    )
    print(f"Alert sent: {event_name}")


def get_recommended_action(event_name, user, source_ip):
    actions = {
        'DeleteBucket - Unauthorised User': (
            f"CRITICAL: '{user}' is not in the approved S3 delete list. "
            f"1. Verify if this deletion was intentional. "
            f"2. Revoke '{user}' S3 delete permissions if unauthorised. "
            f"3. Restore the bucket from backup or S3 versioning if needed."
        ),
        'ConsoleLogin - Brute Force Detected': (
            f"Potential brute force detected against '{user}' from {source_ip}. "
            f"Review login activity for '{user}' from {source_ip}. "
            f"Verify with the user if this was intentional. "
            f"If unrecognized, consider temporarily locking the account and blocking the source IP."
        ),
        'ConsoleLogin': (
            f"Successful console login detected for '{user}' from {source_ip}. "
            f"Verify this access was expected and initiated by the user. "
            f"If unrecognized, investigate for potential account compromise."
        ),
        'CreateAccessKey': (
            f"Access key creation detected by '{user}' from {source_ip}. "
            f"Verify '{user}' is authorized to create access keys. "
            f"If unexpected, disable the key immediately and audit IAM activity."
        ),
        'AttachUserPolicy': (
            f"Policy attachment to a user detected by '{user}' from {source_ip}. "
            f"Confirm '{user}' is authorized to attach policies. "
            f"If unexpected, remove the policy and investigate for privilege escalation."
        ),
        'AttachRolePolicy': (
            f"Policy attachment to a role detected by '{user}' from {source_ip}. "
            f"Confirm '{user}' is authorized to attach role policies. "
            f"If unexpected, remove the policy and investigate for privilege escalation."
        ),
        'TerminateInstances': (
            f"EC2 instance termination detected by '{user}' from {source_ip}. "
            f"Verify '{user}' was authorized to terminate these instances. "
            f"If unexpected, assess blast radius and check for further destructive actions."
        ),
        'StopInstances': (
            f"EC2 instance stop action detected by '{user}' from {source_ip}. "
            f"Verify '{user}' was authorized to stop these instances. "
            f"If unexpected, investigate for potential disruption activity."
        ),
        'CreateBucket': (
            f"S3 bucket created by '{user}' from {source_ip}. "
            f"Verify this was planned. Ensure encryption, versioning, and access controls are configured."
        ),
        'DeleteBucket': (
            f"S3 bucket DELETED by '{user}' from {source_ip}. "
            f"Verify authorization. If unexpected, check for data loss and review recent activity."
        ),
        'PutBucketPolicy': (
            f"Bucket policy added/updated by '{user}' from {source_ip}. "
            f"Review the policy for public access grants. Remove any unauthorized permissions immediately."
        ),
        'DeleteBucketPolicy': (
            f"Bucket policy deleted by '{user}' from {source_ip}. "
            f"Ensure the bucket is still protected by ACLs or other controls."
        ),
    }
    return actions.get(event_name, (
        f"Unclassified security event detected by '{user}' from {source_ip}. "
        f"Investigate the activity and assess potential impact."
    ))


def get_mitre_tag(event_name):
    tags = {
        'DeleteBucket - Unauthorised User': 'T1485 - Data Destruction / Unauthorized Access',
        'ConsoleLogin - Brute Force Detected': 'T1110 - Brute Force',
        'ConsoleLogin': 'T1078 - Valid Accounts',
        'CreateAccessKey': 'T1078 - Valid Accounts - Credential Staging',
        'AttachUserPolicy': 'T1078 - Privilege Escalation',
        'AttachRolePolicy': 'T1078 - Privilege Escalation',
        'TerminateInstances': 'T1485 - Data Destruction',
        'StopInstances': 'T1485 - Data Destruction',
        'CreateBucket': 'T1537 - Transfer Data to Cloud Account',
        'DeleteBucket': 'T1485 - Data Destruction',
        'PutBucketPolicy': 'T1530 - Data from Cloud Storage / Exfiltration Risk',
        'DeleteBucketPolicy': 'T1530 - Data from Cloud Storage',
    }
    return tags.get(event_name, 'Unclassified')
