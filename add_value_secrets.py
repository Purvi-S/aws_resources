import boto3
import pandas as pd

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

def add_value_to_secret(secret_name, new_secret_value):
    client = session.client('secretsmanager')
    try:
        # Replace the existing secret value
        response = client.update_secret(SecretId=secret_name, SecretString=new_secret_value)
    except Exception as e:
            print(f"An error occurred: {e}")
            raise e
    return response

xls=pd.ExcelFile("**Path of the file**")
ecs_clusters = pd.read_excel(xls, 'secretsmanager')
secret_names=ecs_clusters['secret_name']
print(secret_names)
secret_values=ecs_clusters['secret_value']
print(secret_values)
for secret_name, secret_value in zip(secret_names, secret_values):
    print("#################")
    print(secret_name,secret_value)
    print(add_value_to_secret(secret_name, secret_value))
    print("######################")
print("completed")