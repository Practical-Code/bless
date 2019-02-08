import boto3
from botocore.exceptions import ClientError
import base64
import os
import json
import sys
import datetime
import bless_rsa as pem
import configparser
import subprocess



BLESS_HOME = os.getcwd()
print(BLESS_HOME)
BLESSCAKEY = 'bless-ca'
POLICYNAME = "bless_iam_policy"
ROLENAME = "bless_iam_role"
ALIASNAME = "bless_kms_alias"
PASSWORD = 'abc123'
LAMBDAFUNCTION = "bless_lambda"

BLESSCONFIGDIR = 'lambda_configs/'
BLESSCONFFILE = 'bless_deploy.cfg'
BLESSCONFHOME = BLESS_HOME + '/' + BLESSCONFFILE
BLESSCONFDEPLOY = BLESS_HOME + '/' + BLESSCONFIGDIR + BLESSCONFFILE

# Create KMS key

kmsclient = boto3.client('kms')

try: 
  kms_key_res = kmsclient.describe_key( KeyId= 'alias/' + ALIASNAME )
except ClientError as e:
  if e.response['Error']['Code'] == 'NotFoundException':
      print("User Not Found")
      kms_key_res = kmsclient.create_key()
      kms_ca_res = kmsclient.create_alias(
        AliasName='alias/' + ALIASNAME,
        TargetKeyId= kms_key_res['KeyMetadata']['Arn']
      )
  else:
      print("Unexpected error: %s" % e)

if kms_key_res['KeyMetadata']['KeyState'] == 'PendingDeletion':
    print(ALIASNAME + ' is in a pending deletion state choose new alias') 
    sys.exit()
 

print('Created KMS ARN:', kms_key_res['KeyMetadata']['Arn'])

KEY_ID = kms_key_res['KeyMetadata']['Arn']

print(KEY_ID)


# Encrypt password with base64
kms_encrypt_res = kmsclient.encrypt(
    KeyId= KEY_ID,
    Plaintext= PASSWORD
)
ciphertext = kms_encrypt_res['CiphertextBlob']

b64_encode = base64.b64encode(ciphertext)



# Make lambda_configs directory
try:  
    if not os.path.exists(BLESSCONFIGDIR):
        os.makedirs(BLESSCONFIGDIR)
except OSError:  
    print ("Creation of the directory %s failed" % BLESSCONFIGDIR)
else:  
    print ("Successfully created the directory %s " % BLESSCONFIGDIR)


# Create RSA Public and Private Keys
PRIVATEKEY = './' + BLESSCONFIGDIR + '/' +  BLESSCAKEY
subprocess.run(["ssh-keygen", "-t", "rsa", "-N", PASSWORD, "-b", "4096", "-f", PRIVATEKEY, "-C", "bless-ca key"])


# Update the lambda_configs directory 
config = configparser.ConfigParser()
config.read(BLESSCONFHOME)

config.set('Bless CA','default_password', b64_encode.decode("utf-8"))
config.set('Bless CA','ca_private_key_file', BLESSCAKEY)


with open(BLESSCONFDEPLOY, 'w') as configfile:
    config.write(configfile)

# Change permissions on private key
os.chmod(PRIVATEKEY, 444)


# Publish the Lambda
subprocess.run(["make", "publish"])



# Create a policy
BLESSPOLICY = \
    { "Version": "2012-10-17", "Statement": [ { "Action": [ "kms:GenerateRandom", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents" ], "Effect": "Allow", "Resource": "*" }, { "Sid": "AllowKMSDecryption", "Effect": "Allow", "Action": [ "kms:Decrypt", "kms:DescribeKey" ], "Resource": [ KEY_ID ] } ] }



# Create role
bless_role = \
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}




iamclient = boto3.client('iam')

# Looking for bless_iam_policies, if not create a policy and role
try:
  policy_res = iamclient.list_attached_role_policies( RoleName = ROLENAME )
  print('policy_res', policy_res)
  ROLE_ARN = iamclient.get_role( RoleName = ROLENAME)
except ClientError as e:
  if e.response['Error']['Code'] == 'NoSuchEntity':
      print("Policy not found, creating new policy, role and attachment")
      POLICY_ARN = iamclient.create_policy(PolicyName = POLICYNAME,
          PolicyDocument=json.dumps(BLESSPOLICY)
      )
      ROLE_ARN = iamclient.create_role(
          RoleName= ROLENAME,
          AssumeRolePolicyDocument=json.dumps(bless_role),
      )
      print('ROLE_ARN', ROLE_ARN) 
      print('POLICY_ARN', POLICY_ARN) 
      iamclient.attach_role_policy(
          PolicyArn= POLICY_ARN['Policy']['Arn'],
          RoleName= ROLE_ARN['Role']['RoleName']
      )
  else:
      print("Unexpected error: %s" % e)

print(ROLE_ARN)
ROLE_ID = ROLE_ARN['Role']['Arn']

lambdaclient = boto3.client('lambda')
LAMBDAZIP = BLESS_HOME + '/publish/bless_lambda.zip'


# Create Lambda Function 
lambda_res = lambdaclient.create_function(
    FunctionName='bless_lambda',
    Runtime='python3.6',
    Role=ROLE_ID,
    Handler='bless_lambda.lambda_handler',
    Code={'ZipFile': open(LAMBDAZIP, 'rb').read()},
    Timeout=10
)

print('lambda arn', lambda_res)

