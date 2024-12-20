import boto3

def sns_list(session, resources_list, substrings):
    resources_list["sns"] = []
    sns_client = session.client("sns")
    paginator = sns_client.get_paginator('list_topics')
    for response in paginator.paginate():
        for topic in response.get('Topics', []):
            if any(substring in topic['TopicArn'] for substring in substrings):
                resources_list["sns"].append(topic['TopicArn'])
    return resources_list

def sqs_list(session, resources_list, substrings):
    resources_list["sqs"] = []
    sqs_client = session.client("sqs")
    paginator = sqs_client.get_paginator('list_queues')
    for response in paginator.paginate():
        queues = response.get('QueueUrls', [])
        for queue_url in queues:
            queue_name = queue_url.split('/')[-1]
            if any(substring in queue_name for substring in substrings) and "deadletter" not in queue_name:
                resources_list["sqs"].append(queue_url)
    return resources_list

def ecs_list(session, resources_list, substrings):
    resources_list["ecs"] = []
    ecs_client = session.client("ecs")
    clusters = ecs_client.list_clusters()
    matching_clusters = [cluster for cluster in clusters['clusterArns'] if any(substring in cluster for substring in substrings)]
    for cluster_arn in matching_clusters:
        cluster_name = cluster_arn.split('/')[-1]  # Extract the cluster name from the ARN
        paginator = ecs_client.get_paginator('list_services')
        for page in paginator.paginate(cluster=cluster_name):
            resources_list["ecs"].extend(page['serviceArns'])
    return resources_list

def rds_list(session, resources_list, substrings):
    resources_list["rds"] = []
    rds_client = session.client("rds")
    paginator = rds_client.get_paginator('describe_db_instances')
    for response in paginator.paginate():
        for db_instance in response.get('DBInstances', []):
            db_instance_identifier = db_instance['DBInstanceIdentifier']
            if any(substring in db_instance_identifier for substring in substrings):
                resources_list["rds"].append(db_instance_identifier)
    return resources_list

def s3_list(session, resources_list, substrings):
    resources_list["s3"] = []
    s3_client = session.client("s3")
    response = s3_client.list_buckets()
    for bucket in response.get('Buckets', []):
        bucket_name = bucket['Name']
        if any(substring in bucket_name for substring in substrings):
            resources_list["s3"].append(bucket_name)
    return resources_list

def lambda_list(session, resources_list, substrings):
    resources_list["lambda"] = []
    lambda_client = session.client("lambda")
    paginator = lambda_client.get_paginator('list_functions')
    for response in paginator.paginate():
        for function in response.get('Functions', []):
            function_name = function['FunctionName']
            if any(substring in function_name for substring in substrings):
                resources_list["lambda"].append(function_name)
    return resources_list

def glue_list(session, resources_list, substrings):
    resources_list["glue"] = []
    glue_client = session.client("glue")
    paginator = glue_client.get_paginator('get_jobs')
    for response in paginator.paginate():
        for job in response.get('Jobs', []):
            job_name = job['Name']
            if any(substring in job_name for substring in substrings):
                resources_list["glue"].append(job_name)
    return resources_list

def secrets_manager_list(session, resources_list, substrings):
    resources_list["secrets_manager"] = []
    secrets_manager_client = session.client("secretsmanager")
    paginator = secrets_manager_client.get_paginator('list_secrets')
    for response in paginator.paginate():
        for secret in response.get('SecretList', []):
            secret_name = secret['Name']
            if any(substring in secret_name for substring in substrings):
                resources_list["secrets_manager"].append(secret_name)
    return resources_list

def ssm_parameters_list(session, resources_list, substrings):
    resources_list["ssm_parameters"] = []
    ssm_client = session.client("ssm")
    paginator = ssm_client.get_paginator('describe_parameters')
    for response in paginator.paginate():
        for parameter in response.get('Parameters', []):
            parameter_name = parameter['Name']
            if any(substring in parameter_name for substring in substrings):
                resources_list["ssm_parameters"].append(parameter_name)
    return resources_list

def step_functions_list(session, resources_list, substrings):
    resources_list["step_functions"] = []
    sfn_client = session.client("stepfunctions")
    paginator = sfn_client.get_paginator('list_state_machines')
    for response in paginator.paginate():
        for state_machine in response.get('stateMachines', []):
            state_machine_name = state_machine['name']
            if any(substring in state_machine_name for substring in substrings):
                resources_list["step_functions"].append(state_machine['stateMachineArn'])
    return resources_list

def ec2_list(session, resources_list, substrings):
    resources_list["ec2"] = []
    ec2_client = session.client("ec2")
    reservations = ec2_client.describe_instances().get('Reservations', [])

    for reservation in reservations:
        for instance in reservation['Instances']:
            # Get the instance name from the tags
            instance_name = next(
                (tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'),
                instance['InstanceId']  # Fallback to instance ID if name tag is not set
            )
            # Check if any of the substrings are in the instance name
            if any(substring in instance_name for substring in substrings):
                resources_list["ec2"].append(instance['InstanceId'])

    return resources_list

def cloudwatch_log_groups_list(session, resources_list, substrings):
    resources_list["cloudwatch_log_groups"] = []
    logs_client = session.client("logs")
    paginator = logs_client.get_paginator('describe_log_groups')

    for page in paginator.paginate():
        for log_group in page.get('logGroups', []):
            log_group_name = log_group['logGroupName']
            if any(substring in log_group_name for substring in substrings):
                resources_list["cloudwatch_log_groups"].append(log_group_name)

    return resources_list

def ecr_list(session, resources_list, substrings):
    resources_list["ecr"] = []
    ecr_client = session.client("ecr")
    paginator = ecr_client.get_paginator('describe_repositories')

    for page in paginator.paginate():
        for repo in page.get('repositories', []):
            repo_name = repo['repositoryName']
            if any(substring in repo_name for substring in substrings):
                resources_list["ecr"].append(repo_name)

    return resources_list

def iam_users_list(session, resources_list, substrings):
    resources_list["iam_users"] = []
    iam_client = session.client("iam")
    paginator = iam_client.get_paginator('list_users')

    for page in paginator.paginate():
        for user in page.get('Users', []):
            user_name = user['UserName']
            if any(substring in user_name for substring in substrings):
                resources_list["iam_users"].append(user_name)

    return resources_list

def iam_groups_list(session, resources_list, substrings):
    resources_list["iam_groups"] = []
    iam_client = session.client("iam")
    paginator = iam_client.get_paginator('list_groups')

    for page in paginator.paginate():
        for group in page.get('Groups', []):
            group_name = group['GroupName']
            if any(substring in group_name for substring in substrings):
                resources_list["iam_groups"].append(group_name)

    return resources_list

def iam_roles_list(session, resources_list, substrings):
    resources_list["iam_roles"] = []
    iam_client = session.client("iam")
    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page.get('Roles', []):
            role_name = role['RoleName']
            if any(substring in role_name for substring in substrings):
                resources_list["iam_roles"].append(role_name)

    return resources_list

def iam_policies_list(session, resources_list, substrings):
    resources_list["iam_policies"] = []
    iam_client = session.client("iam")
    paginator = iam_client.get_paginator('list_policies')

    for page in paginator.paginate(Scope='Local'):  # 'Local' for customer-managed policies
        for policy in page.get('Policies', []):
            policy_name = policy['PolicyName']
            if any(substring in policy_name for substring in substrings):
                resources_list["iam_policies"].append(policy_name)

    return resources_list

def dynamodb_tables_list(session, resources_list):
    substrings=["terraform-locks","terraform-state"]
    resources_list["dynamodb_tables"] = []
    dynamodb_client = session.client("dynamodb")
    paginator = dynamodb_client.get_paginator('list_tables')

    for page in paginator.paginate():
        for table_name in page.get('TableNames', []):
            if any(substring in table_name for substring in substrings):
                resources_list["dynamodb_tables"].append(table_name)

    return resources_list

def eks_clusters_list(session, resources_list, substrings):
    resources_list["eks_clusters"] = []
    eks_client = session.client("eks")
    clusters = eks_client.list_clusters()['clusters']

    for cluster_name in clusters:
        if any(substring in cluster_name for substring in substrings):
            resources_list["eks_clusters"].append(cluster_name)

    return resources_list

def route53_hosted_zones_and_records_list(session, resources_list, substrings):
    resources_list["route53_hosted_zones"] = []
    resources_list["route53_records"] = []
    route53_client = session.client("route53")
    hosted_zones_paginator = route53_client.get_paginator('list_hosted_zones')
    records_paginator = route53_client.get_paginator('list_resource_record_sets')

    # List and filter hosted zones
    for page in hosted_zones_paginator.paginate():
        for hosted_zone in page['HostedZones']:
            hosted_zone_name = hosted_zone['Name'].rstrip('.')
            if any(substring in hosted_zone_name for substring in substrings):
                resources_list["route53_hosted_zones"].append(hosted_zone_name)

                # List and filter records for the matched hosted zones
                for record_page in records_paginator.paginate(HostedZoneId=hosted_zone['Id']):
                    for record_set in record_page['ResourceRecordSets']:
                        record_set_name = record_set['Name'].rstrip('.')
                        if any(substring in record_set_name for substring in substrings):
                            record = {
                                "HostedZoneName": hosted_zone_name,
                                "RecordName": record_set_name,
                                "Type": record_set["Type"],
                                "TTL": record_set.get("TTL"),
                                "Records": [record.get("Value") for record in record_set.get("ResourceRecords", [])]
                            }
                            resources_list["route53_records"].append(record)

    return resources_list

def kms_keys_list(session, resources_list, substrings):
    resources_list["kms_keys"] = []
    kms_client = session.client("kms")
    paginator = kms_client.get_paginator('list_keys')

    for page in paginator.paginate():
        for key in page['Keys']:
            key_id = key['KeyId']
            # Get key description
            key_metadata = kms_client.describe_key(KeyId=key_id)
            key_description = key_metadata.get('KeyMetadata', {}).get('Description', '')

            if any(substring in key_description for substring in substrings):
                key_info = {
                    "KeyId": key_id,
                    "Description": key_description
                }
                resources_list["kms_keys"].append(key_info)

    return resources_list

def kms_aliases_list(session, resources_list, substrings):
    resources_list["kms_aliases"] = []
    kms_client = session.client("kms")
    paginator = kms_client.get_paginator('list_aliases')

    for page in paginator.paginate():
        for alias in page['Aliases']:
            alias_name = alias['AliasName']
            # Alias names are prefixed with 'alias/', which might need to be removed or kept based on your needs
            if any(substring in alias_name for substring in substrings):
                resources_list["kms_aliases"].append(alias_name)

    return resources_list

def elb_classic_load_balancers_list(session, resources_list, substrings):
    resources_list["classic_load_balancers"] = []
    elb_client = session.client("elb")
    paginator = elb_client.get_paginator('describe_load_balancers')

    for page in paginator.paginate():
        for lb in page['LoadBalancerDescriptions']:
            lb_name = lb['LoadBalancerName']
            if any(substring in lb_name for substring in substrings):
                resources_list["classic_load_balancers"].append(lb_name)

    return resources_list

def elbv2_application_load_balancers_list(session, resources_list, substrings):
    resources_list["application_load_balancers"] = []  # Initialize the list in the provided dictionary
    elbv2_client = session.client('elbv2')  # Use the 'elbv2' client for Application Load Balancers
    paginator = elbv2_client.get_paginator('describe_load_balancers')

    for page in paginator.paginate():
        for lb in page['LoadBalancers']:
            lb_name = lb['LoadBalancerName']
            lb_type = lb['Type']
            if lb_type == 'application' and any(substring in lb_name for substring in substrings):
                resources_list["application_load_balancers"].append(lb_name)

    return resources_list

def elbv2_network_load_balancers_list(session, resources_list, substrings):
    resources_list["network_load_balancers"] = []
    elbv2_client = session.client('elbv2')  # Use the 'elbv2' client for Network Load Balancers
    paginator = elbv2_client.get_paginator('describe_load_balancers')

    for page in paginator.paginate():
        for lb in page['LoadBalancers']:
            lb_name = lb['LoadBalancerName']
            lb_type = lb['Type']
            if lb_type == 'network' and any(substring in lb_name for substring in substrings):
                resources_list["network_load_balancers"].append(lb_name)

    return resources_list

def elasticache_clusters_list(session, resources_list, substrings):
    resources_list["elasticache_clusters"] = []
    elasticache_client = session.client("elasticache")

    paginator = elasticache_client.get_paginator('describe_cache_clusters')
    for page in paginator.paginate(ShowCacheNodeInfo=True):
        for cluster in page['CacheClusters']:
            cluster_id = cluster['CacheClusterId']
            if any(substring in cluster_id for substring in substrings):
                resources_list["elasticache_clusters"].append(cluster_id)

    return resources_list

def autoscaling_groups_list(session, resources_list, substrings):
    resources_list["autoscaling_groups"] = []
    autoscaling_client = session.client("autoscaling")

    paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
    for page in paginator.paginate():
        for group in page['AutoScalingGroups']:
            group_name = group['AutoScalingGroupName']
            if any(substring in group_name for substring in substrings):
                resources_list["autoscaling_groups"].append(group_name)

    return resources_list

def apigateway_apis_list(session, resources_list, substrings):
    resources_list["apigateway_apis"] = []
    apigateway_client = session.client("apigateway")

    paginator = apigateway_client.get_paginator('get_rest_apis')
    for page in paginator.paginate():
        for api in page['items']:
            api_name = api['name']
            if any(substring in api_name for substring in substrings):
                resources_list["apigateway_apis"].append(api_name)

    return resources_list

def eventbridge_rules_list(session, resources_list, substrings):
    resources_list["eventbridge_rules"] = []
    events_client = session.client("events")

    paginator = events_client.get_paginator('list_rules')
    for page in paginator.paginate():
        for rule in page['Rules']:
            rule_name = rule['Name']
            if any(substring in rule_name for substring in substrings):
                resources_list["eventbridge_rules"].append(rule_name)

    return resources_list