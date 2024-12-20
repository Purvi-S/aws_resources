import boto3
import listing_aws as list
import json


def aws_list(session,substring):
    resources_list = {}

    resources_list = list.sqs_list(session,resources_list,substring)
    resources_list = list.sns_list(session,resources_list,substring)
    resources_list = list.ecs_list(session,resources_list,substring)
    resources_list = list.rds_list(session,resources_list,substring)
    resources_list = list.s3_list(session,resources_list,substring)
    resources_list = list.lambda_list(session,resources_list,substring)
    resources_list = list.glue_list(session,resources_list,substring)
    resources_list = list.ssm_parameters_list(session,resources_list,substring)
    resources_list = list.secrets_manager_list(session,resources_list,substring)
    resources_list = list.step_functions_list(session,resources_list,substring)
    resources_list = list.ec2_list(session,resources_list,substring)
    resources_list = list.cloudwatch_log_groups_list(session,resources_list,substring)
    resources_list = list.ecr_list(session,resources_list,substring)
    resources_list = list.iam_roles_list(session,resources_list,substring)
    resources_list = list.iam_policies_list(session,resources_list,substring)
    resources_list = list.dynamodb_tables_list(session,resources_list)
    resources_list = list.route53_hosted_zones_and_records_list(session,resources_list,substring)
    resources_list = list.kms_keys_list(session,resources_list,substring)
    resources_list = list.kms_aliases_list(session,resources_list,substring)
    resources_list = list.elbv2_network_load_balancers_list(session,resources_list,substring)
    resources_list = list.elasticache_clusters_list(session,resources_list,substring)
    resources_list = list.eventbridge_rules_list(session,resources_list,substring)

    return resources_list

if __name__ == "__main__":
    # Define the substring you are looking for
    substring = [] #eg. "dev"

    # Your AWS credentials and the region
    region_name="<Enter Region>"
    aws_access_key_id = "<Enter access key>"
    aws_secret_access_key = "<Enter secret access key>"
    aws_session_token = "<Enter Token>"

    # Create a session using your AWS credentials
    session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region_name,
    aws_session_token=aws_session_token
    )

    resources_list=aws_list(session,substring)

    # Save to a new file
    with open('aws_resources_with_substring.json', 'w') as f:
        json.dump(resources_list, f, indent=4)

    print("Resources with the substring saved to aws_resources_with_substring.json")
