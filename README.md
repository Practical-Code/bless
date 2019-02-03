![alt text](bless_logo.png "BLESS")
# BLESS - Bastion's Lambda Ephemeral SSH Service
[![Build Status](https://travis-ci.org/Netflix/bless.svg?branch=master)](https://travis-ci.org/Netflix/bless) [![Test coverage](https://coveralls.io/repos/github/Netflix/bless/badge.svg?branch=master)](https://coveralls.io/github/Netflix/bless) [![Join the chat at https://gitter.im/Netflix/bless](https://badges.gitter.im/Netflix/bless.svg)](https://gitter.im/Netflix/bless?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![NetflixOSS Lifecycle](https://img.shields.io/osslifecycle/Netflix/bless.svg)]()

BLESS is an SSH Certificate Authority that runs as an AWS Lambda function and is used to sign SSH
public keys.

SSH Certificates are an excellent way to authorize users to access a particular SSH host,
as they can be restricted for a single use case, and can be short lived.  Instead of managing the
authorized_keys of a host, or controlling who has access to SSH Private Keys, hosts just
need to be configured to trust an SSH CA.

BLESS should be run as an AWS Lambda in an isolated AWS account.  Because BLESS needs access to a
private key which is trusted by your hosts, an isolated AWS account helps restrict who can access
that private key, or modify the BLESS code you are running.

AWS Lambda functions can use an AWS IAM Policy to limit which IAM Roles can invoke the Lambda
Function.  If properly configured, you can restrict which IAM Roles can request SSH Certificates.
For example, your SSH Bastion (aka SSH Jump Host) can run with the only IAM Role with access to
invoke a BLESS Lambda Function configured with the SSH CA key trusted by the instances accessible
to that SSH Bastion.

## Getting Started
These instructions are to get BLESS up and running in your local development environment.

#### Authorize CodeBuild using OAUTH to have access to GitHub

In an AWS account navigate to the CodeBuild console and connect your AWS account to your GitHub account. In the CodeBuild console, select "Create Build Project". Under Source, select "Github" and select "Connect using OAUTH" and select the "Connect to GitHub" button. On the GitHub Authorize application page, for organization access , choose "Request access" and select the bless repository, and then select "Authorize application". After a connection to a GitHub account has been made, finishing building the project will not be necessary.

Fork this repository into a personal account.

## BLESS Deployment Instructions 

In an AWS account, navigate to the AWS CloudFormation console and select "Create Stack".

Choose "Design a template" and cut and paste the yaml located in bless-deploy.cf in the bless_cloudformation folder into the CloudFormation designer.

Change the location in the CloudFormation template from https://github.com/Practical-Code/bless.git to the location of your forked repository.

Name and create the CloudFormation stack.

A Lambda function named bless_lambda will now be created and will be able to sign certficates.

## Create a Testing environment and Use BLESS
Deploy the bash script in the folder bless_bash named ec2_deploy on a command line or follow the step by step instructions. 

If using the bash script, change the variable for AWS_REGION at the top of the ec2_deploy script if not in region us-east-1.

Running this script will:

- Create a Key Pair.
- Create a new EC2 instance everytime the script is run.
- Configure the EC2 instance to trust the cert.
- Build a BLESS client.
- Log on to the EC2 instance with a new cert.


### Step by Step Instrutions to Create an EC2 Instance and Configure the Instance to Trust the Certificate.
Create a keypair and an EC2 instance using the AWS EC2 console. 

Save the keypair to a key folder and change the key's permissions to 600.

        	$ chmod 600 KEYPAIRNAME 
        
Log on to the EC2 instance in the command line.

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
        
Exit the EC2 instance:
		
		$ exit 
        
#### Generate New Certificates

Generate a new certificate:

		$ ssh-keygen -f ~/.ssh/blessid -b 4096 -t rsa -C 'Temporary key for BLESS certificate' -N ''  
		$ ssh-keygen -y -f ~/.ssh/blessid > ~/.ssh/blessid.pub  
		$ touch ~/.ssh/blessid-cert.pub  
		$ ln -s ~/.ssh/blessid-cert.pub ~/.ssh/blessid-cert

Run the bless_client in the bless_client directory. To generate new certificates, replace the information in the bless_client with your own. 

		$ ./bless_client.py

Output:

		$ Usage: bless_client.py region lambda_function_name bastion_user bastion_user_ip remote_usernames bastion_ips bastion_command <id_rsa.pub to sign> <output id_rsa-cert.pub> [kmsauth token]

Example:

		$ ./bless_client.py us-east-1 LAMBDANAME aaaa 1.1.1.1 ec2-user $(curl api.ipify.org) "" ~/.ssh/blessid.pub ~/.ssh/blessid-cert.pub

  
Sign in with the new certificate. 

		$ ssh -i ~/.ssh/blessid ec2-user@PUBLICIPADDRESS


## Project resources
- Source code <https://github.com/netflix/bless>
- Issue tracker <https://github.com/netflix/bless/issues>
