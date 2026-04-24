def get_team_from_event(event_name):
    mapping = {
        'CreateAccessKey': 'security',
        'AttachUserPolicy': 'security',
        'AttachRolePolicy': 'security',
        'ConsoleLogin - Brute Force Detected': 'security',
        'TerminateInstances': 'infra',
        'StopInstances': 'infra',
        'CreateBucket': 'cloud',
        'DeleteBucket': 'cloud',
        'PutBucketPolicy': 'security',
        'DeleteBucketPolicy': 'security'
    }
    return mapping.get(event_name, 'general')
