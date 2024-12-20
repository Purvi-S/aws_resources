import boto3
import os
from botocore.config import Config

region_name="**Enter region**"

aws_access_key_id = "**Enter access key**"

aws_secret_access_key = "**Enter secret key**"

aws_session_token = "**Enter Token**"

endpoint_url = os.environ.get('LOCAL_AWS_ENDPOINT_S3', None)
print(endpoint_url)
bucket="**Enter bucket name**"
prefix="**Enter prefix**"

client = boto3.client('s3',
                      region_name=region_name,
                      aws_access_key_id=aws_access_key_id,
                      aws_secret_access_key=aws_secret_access_key,
                      aws_session_token=aws_session_token,
                      config=Config(signature_version='s3v4'),
                      endpoint_url="**enter endpoint url**")
session = boto3.session.Session()
print(session.region_name)
print(client.meta.endpoint_url)
url = "{}/{}/{}".format(endpoint_url, bucket, prefix)
print(url)
response = client.list_objects_v2(
        Bucket=bucket,
        Prefix=prefix,
        MaxKeys=10
        )

print(response)
