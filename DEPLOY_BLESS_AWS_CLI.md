## Deploying Netflix’s Bastion's Lambda Ephemeral SSH Service (BLESS) with AWS CLI Commands

Netflix Bastion's Lambda Ephemeral SSH Service is an SSH Certificate Authority that uses an AWS Lambda function to sign public keys.

  
Benefits of Certificate Authorities:

-   Authorize users to access a certain host.
    
-   Can be generated for single use.
    
-   Certificate expiration can be adjusted to satisfy needs.
    
-   Management of user public keys to instances is simplified.


This post will walkthrough deploying BLESS using AWS CLI commands. 

All general commands are for a Mac and Linux OS and a Linux subsystem installed on Windows.

Prerequisites:

-   AWS CLI, Python 3.6, Docker, Vim and SSH access to Github.

# Getting Started

Clone Netflix’s BLESS repo:

		$ git clone https://github.com/Netflix/bless.git

Navigate into the BLESS repo:

		$ cd bless

Compile Lambda dependencies using a docker container running Amazon Linux:

		$ sudo make lambda-deps
		
This will create a directory called aws_lambda_libs with all of the required dependencies.

## Create AWS Resources and RSA Keys

Create an AWS KMS key. This KMS key will encrypt the password that will be attached to the RSA private key:

		$ aws kms create-key --query KeyMetadata.KeyId --output text

This command will print out the KMS key id, use the key id to retrieve the KMS key ARN (Amazon Resource Name).

Retrieve the KMS key ARN:

		$ aws kms describe-key --key-id $KEY_ID --query KeyMetadata.Arn --output text

This command will print out the KMS key ARN, use the ARN to create a KMS key alias. 

Create an alias for the KMS key:

		$ aws kms create-alias --alias-name alias/$ALIASNAME --target-key-id $KEY_ARN

Create a directory in bless called lambda_configs, which will store the the lambda configurations file, and the RSA private and public keys:

		$ mkdir lambda_configs

## **Protect Certificate Authority Private Key**

In the lambda_configs directory, generate a password protected RSA private key pair:

		$ ssh-keygen -t rsa -N "$PASSWORD" -b 4096 -f bless-ca -C "SSH CA Key"

Change the permissions on the RSA private key file, otherwise Lambda will fail to read the key:

		$ chmod 444 bless-ca

Cat the bless-ca.pub RSA key and save the output for later:

		$ cat bless-ca.pub

In the lambda_configs directory, encrypt the kms key with base64:

		$ aws kms encrypt --key-id $KEY_ID --plaintext $PASSWORD

Create a config file for BLESS called bless_deploy.cfg:

		$ vi bless_deploy.cfg 
		
Copy the code from the repo in bless_deploy_example.cfg and paste into your  bless_deploy.cfg file.

    #This section and its options are optional
    [Bless Options]
    #Number of seconds +/- the issued time for the certificate to be valid
    certificate_validity_after_seconds = 120
    certificate_validity_before_seconds = 120
    #Minimum number of bits in the system entropy pool before requiring an additional seeding step
    entropy_minimum_bits = 2048
    #Number of bytes of random to fetch from KMS to seed /dev/urandom
    random_seed_bytes = 256
    #Set the logging level
    logging_level = INFO
    #Comma separated list of the SSH Certificate extensions to include. Not specifying this uses the ssh-keygen defaults:
    #certificate_extensions = permit-X11-forwarding,permit-agent-forwarding,permit-port-forwarding,permit-pty,permit-user-rc
    #Username validation options are described in bless_request.py:USERNAME_VALIDATION_OPTIONS
    #Configure how bastion_user names are validated.
    #username_validation = useradd
    #Configure how remote_usernames names are validated.
    #remote_usernames_validation = principal
    #Configure a regex of blacklisted remote_usernames that will be rejected for any value of remote_usernames_validation.
    #remote_usernames_blacklist = root|admin.*
    #These values are all required to be modified for deployment
    
    [Bless CA]
    
    #You must set an encrypted private key password for each AWS Region you deploy into
    #for each aws region specify a config option like '{}_password'.format(aws_region)
    #us-east-1_password = <INSERT_US-EAST-1_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>
    #us-west-2_password = <INSERT_US-WEST-2_KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>
    #Or you can set a default password. Region specific password have precedence over the default
    default_password = <KMS_ENCRYPTED_BASE64_ENCODED_PEM_PASSWORD_HERE>
    #Specify the file name of your SSH CA's Private Key in PEM format.
    ca_private_key_file = bless-ca
    #Or specify the private key directly as a base64 encoded string.
    #ca_private_key = <INSERT_YOUR_ENCRYPTED_KEY>


Under **default** password, paste the output of the AWS KMS encrypt command. This is your encrypted password. 

	ex. default password = AQIC ...... ==

Under **ca_private_key_file** set it to equal bless-ca.

	ex. ca_private_key_file = bless-ca

Navigate back into the bless directory and publish a zip file to give to the Lambda to upload:

		$ make publish

## **Create AWS IAM Policies and IAM Roles**

Create a document for an IAM policy. Insert the KMS key ARN in the policy. This will allow for the Lambda to use the decrypt function on the KMS key.

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "kms:GenerateRandom",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ],
          "Effect": "Allow",
          "Resource": "*"
        },
        {
          "Sid": "AllowKMSDecryption",
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:DescribeKey"
          ],
          "Resource": [
            "KMSKEYARN"
          ]
        }
      ]
    }

  

Create the IAM policy:

		$ aws iam create-policy --policy-name POLICYNAME --policy-document "BLESSPOLICY" --query Policy.Arn --output text

  
Create a JSON document for an IAM Role that will allow the role to trust Lambda.

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "lambda.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }

Create an IAM role:

		$ aws iam create-role --role-name ROLENAME --assume-role-policy-document "BLESSROLE.json" --query Role.Arn --output text

Attach the policy to the role:

		$ aws iam attach-role-policy --role-name ROLENAME --policy-arn "POLICY_ARN"

Create a Lambda function:

		$ aws lambda create-function --function-name LAMBDA-FUNCTION-NAME --runtime python3.6 --role ROLEARN --handler bless_lambda.lambda_handler --zip-file fileb://./publish/bless_lambda.zip --timeout 10

The Lambda will now be able to sign certificates!

## Create a Testing Environment 
Create a key pair to login to an EC2 Instance with. If you already have a key pair associated with your AWS CLI, feel free to use that.

		$ aws ec2 create-key-pair --key-name KEYPAIRNAME --query 'KeyMaterial' --output text > KEYPAIRNAME


Change the permissions on the key pair:

		$ chmod 600 KEYPAIRNAME

Move the key pair to an SSH directory to easily locate it:

		$ mv KEYPAIRNAME ~/.ssh

Choose a security group for the EC2 Instance and copy the security group ID:

		$ aws ec2 describe-security-groups

Choose a subnet for the EC2 instance and copy the subnet ID:

		$ aws ec2 describe-subnets

Create an EC2 Instance:

		$ aws ec2 run-instances --image-id ami-009d6802948d06e52 --count 1 --instance-type t2.micro --key-name $KEYPAIRNAME --security-group-ids $SECURITYGROUPID --subnet-id $SUBNETID

## **Enable BLESS Certificate on the EC2 Instance**

Retrieve your EC2 Instance’s public IP address:

		$ aws ec2 describe-instances --instance-ids INSTANCEID --query Reservations[*].Instances[*].PublicIpAddress --output text

SSH onto the EC2 Instance:

		$ ssh -i ~/.ssh/KEYPAIRNAME ec2-user@PUBLICIP

Go to root user and navigate into the sshd_config file:

		$ sudo su
		$ cd /etc/ssh
		$ vi sshd_config

Add “TrustedUserCAKeys /etc/ssh/cas.pub” to the end of the sshd_config file and create it.

		$ touch cas.pub

Change the permissions on cas.pub:

		$ chmod 600 cas.pub

Go in to the cas.pub file and paste in the bless-ca.pub key:

		$ vi /etc/ssh/cas.pub

Restart the sshd:

		$ systemctl restart sshd
		
Exit the EC2 Instance:
		
		$ exit 

## **Generate New Certificates**

Create a new certificate:

		$ ssh-keygen -f ~/.ssh/blessid -b 4096 -t rsa -C 'Temporary key for BLESS certificate' -N ''  
		$ ssh-keygen -y -f ~/.ssh/blessid > ~/.ssh/blessid.pub  
		$ touch ~/.ssh/blessid-cert.pub  
		$ ln -s ~/.ssh/blessid-cert.pub ~/.ssh/blessid-cert

Run the bless_client in the bless_client directory. To generate new certificates, replace the information in the bless_client with your own. 
		$ cd bless_client
		$ ./bless_client.py

Output:

		$ Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_usernames bastion_ips bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub> [kmsauth token]

Example:

		$ ./bless_client.py us-east-1 $LAMBDA-NAME aaaa 1.1.1.1 ec2-user $(curl api.ipify.org) "" ~/.ssh/blessid.pub ~/.ssh/blessid-cert.pub

  
Sign in with the new certificate. 

		$ ssh -i ~/.ssh/blessid ec2-user@PUBLICIPADDRESS



### **Project Resources**
-   Source code  [https://github.com/netflix/bless](https://github.com/netflix/bless)
-   Reference  [https://www.youtube.com/watch?v=j-ks2MBeUWw](https://www.youtube.com/watch?v=j-ks2MBeUWw) 

