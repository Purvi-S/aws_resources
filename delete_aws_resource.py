import boto3
import pandas as pd

def stop_and_delete_services(cluster_name):
    try:
        # Describe services in the cluster
        services_response = ecs.list_services(cluster=cluster_name)
        service_arns = services_response['serviceArns']

        for service_arn in service_arns:
            # Stop service by setting desired count to 0
            ecs.update_service(
                cluster=cluster_name,
                service=service_arn.split('/')[-1],
                desiredCount=0
            )

        # Wait for services to stop
        waiter = ecs.get_waiter('services_stable')
        waiter.wait(
            cluster=cluster_name,
            services=service_arns,
            WaiterConfig={
                'Delay': 10,
                'MaxAttempts': 60
            }
        )

        # Delete services
        for service_arn in service_arns:
            ecs.delete_service(
                cluster=cluster_name,
                service=service_arn.split('/')[-1]
            )

        print("All services in the cluster stopped and deleted successfully.")

    except ecs.exceptions.ClusterNotFoundException:
        print(f"ECS cluster '{cluster_name}' not found.")

    except ecs.exceptions.ServiceNotFoundException:
        print("Service not found.")

    except Exception as e:
        print(f"An error occurred: {e}")

def delete_ecs_cluster(cluster_name):
    try:
        # Delete ECS cluster
        response = ecs.delete_cluster(
            cluster=cluster_name
        )
        print(f"ECS cluster '{cluster_name}' has been deleted successfully.")

    except ecs.exceptions.ClusterNotFoundException:
        print(f"ECS cluster '{cluster_name}' not found.")

    except ecs.exceptions.ClusterContainsServicesException:
        print("The cluster contains active services. Stopping and deleting services first.")
        stop_and_delete_services(cluster_name)
        # Retry cluster deletion after services are stopped and deleted
        delete_ecs_cluster(cluster_name)

    except Exception as e:
        print(f"An error occurred: {e}")

def delete_rds(instance):
    try:
        rds.modify_db_instance(
                                DBInstanceIdentifier=instance,
                                DeletionProtection=False,
                                ApplyImmediately=True
                              )
        response = rds.delete_db_instance(DBInstanceIdentifier=instance, SkipFinalSnapshot=True)
        print(f"Deleted RDS instance: {instance}")
    except Exception as e:
        print(f"Error deleting RDS instance: {instance}")
        print(e)

def delete_glue(job):
    try:
        response = glue.delete_job(JobName=job)
        print(f"Deleted Glue job: {job}")
    except Exception as e:
        print(f"Error deleting Glue job: {job}")
        print(e)

def delete_lambda(lambdas_name):
    try:
        response = lambda_client.delete_function(FunctionName=lambdas_name)
        print(f"Deleted Lambda job: {lambdas_name}")
    except Exception as e:
        print(f"Error deleting Lambda job: {lambdas_name}")
        print(e)

def delete_step_func(step_func):
    del_step_arn=[]
    try:
        response = stepfunc.list_state_machines()
        for state_machine in response['stateMachines']:
            if state_machine['name'] in step_func:
                del_step_arn.append(state_machine['stateMachineArn'])
    except Exception as e:
        print(f"Error retrieving state machine ARN: {e}")
    for del_step in del_step_arn:
        try:
            response = stepfunc.delete_state_machine(stateMachineArn=del_step)
            print(f"Deleted step func : {del_step}")
        except Exception as e:
            print(f"Error deleting state machine '{del_step}': {e}")

def delete_sqs(url):
    try:
        response=sqs.delete_queue(QueueUrl=url)
        print(f"Deleted SQS : {url}")
    except Exception as e:
        print(f"Error deleting SQS queue: {e}")

def delete_sns(list):
    for topic_arn in list:
        try:
            response=sns.delete_topic(TopicArn=topic_arn)
            print(f"SNS topic '{topic_arn}' deleted successfully.")
        except Exception as e:
            print(f"Error deleting SNS topic: {e}")

def delete_secret(secret_name):
    client = session.client('secretsmanager')
    try:
        # Delete the secret
        response = client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
    except Exception as e:
        print(f"An error occurred: {e}")
        raise e
    return response

region_name="**Enter region**"

aws_access_key_id = "**Enter access key**"

aws_secret_access_key = "**Enter secret key**"

aws_session_token = "**Enter Token**"

session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region_name,
    aws_session_token=aws_session_token
)

ecs = session.client('ecs')
rds = session.client('rds')
glue = session.client('glue')
lambda_client= session.client('lambda')
stepfunc=session.client('stepfunctions')
sqs=session.client('sqs')
sns=session.client('sns')

xls=pd.ExcelFile("/Users/purshant/Desktop/test/deleteAWS.xlsx")

ecs_clusters = pd.read_excel(xls, 'ECS')
rds_instances = pd.read_excel(xls, 'RDS')
glue_jobs = pd.read_excel(xls, 'GlueJobs')
lambdas=pd.read_excel(xls, 'Lambdas')
step_funcs=pd.read_excel(xls,'StepFunction')
sqs_list=pd.read_excel(xls,'SQS')
sns_list=pd.read_excel(xls,'SNS')
secret_list=pd.read_excel(xls, 'secretsmanager')

print("###### ECS #########")
for cluster in ecs_clusters['Resource']:
    delete_ecs_cluster(cluster)

print("###### RDS #########")
for instance in rds_instances['Resource']:
    delete_rds(instance)

print("###### Glue #########")
for job in glue_jobs['Resource']:
    delete_glue(job)

print("##### Lambdas ######")
for lambda_func in lambdas['Resource']:
    delete_lambda(str(lambda_func))

print("##### Step Functions ######")
delete_step_func(list(step_funcs['Resource']))

print("##### SQS #####")
for sqs_name in sqs_list['Resource']:
    try:
        response = sqs.get_queue_url(QueueName=sqs_name)
        queue_url = response['QueueUrl']
        delete_sqs(queue_url)
    except sqs.exceptions.QueueDoesNotExist:
        print(f"Queue '{sqs_name}' does not exist.")
    except Exception as e:
        print(f"Error getting queue URL: {e}")

print("##### SNS #####")
response = sns.list_topics()
del_sns_list=[]
try:
    for sns_name in sns_list['Resource']:
        for topic in response.get('Topics', []):
            if sns_name == topic.get('TopicArn').split(':')[-1]:
                del_sns_list.append(topic.get('TopicArn'))
    print(del_sns_list)
    delete_sns(del_sns_list)
except sns.exceptions.ResourceNotFoundException:
    print(f"SNS topic '{topic_arn}' not found.")
except Exception as e:
    print(f"Error getting Topic ARN: {e}")


print("####### secretmanager ########")
for secret_name in secret_list['secret_name']:
    print(secret_name)
    print(delete_secret(secret_name))
    print("Deleted secrets")
