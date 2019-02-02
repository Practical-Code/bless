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

These instructions will create an AWS CodeBuild project in the AWS console. 

The two options in the AWS CodeBuild console for operating systems are Ubuntu 14 and Windows. This CodeBuild project can not be created with one of those two operating systems. The operating system can be changed through the AWS CLI, where many more options for operating systems are available.

Since this GitHub repository is private, this project will first need to be built inside the AWS CodeBuild console and then the operating system will have to be updated using AWS CLI. 

### BLESS Deployment Instructions 

#### AWS IAM

In an AWS account, navigate to the CloudFormation console.

Select "Create Stack"

Either choose "Design a template" and cut and paste the yaml located in bless-deploy.cf in the bless_cloudformation folder into the CloudFormation designer or upload the file under "Upload a template to Amazon S3" 
    
Attach that policy to an AWS CodeBuild service role.

### AWS CodeBuild
Navigate to the AWS CodeBuild Console and select **Create build project**.

#### Project Configuration 
Name the project and give the project a description. 

#### Source
Under Source, select **GitHub**.

Under repository, select **Repository in my GitHub account**. 

Connect to GitHub using a personal access token. 
Personal access tokens can be generated in a user's GitHub account in setting, using developer settings. 

For GitHub repository, select **PracticalCode/bless-deploy**.

#### Environment 

For Environment Image, choose **Managed Image**.

For Operating system, choose **Ubuntu** and **Python** and **aws/codebuild/python3.6.5**

For Service role, choose the role that was created for CodeBuild.

#### BuildSpec

Choose **Use a buildspec file**.
The buildspec will be found by CodeBuild in the GitHub repository.

Select **Create build project**.

### Update CodeBuild Project with AWS CLI
Make sure AWS CLI is set up and configured. https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html 

Update the BLESS CodeBuild project to a python-3.4-amazonlinux-64:2.1.6 image. Replace $PROJECT_NAME with the name of the CodeBuild project.

       $ aws codebuild update-project --environment image="aws/codebuild/eb-python-3.4-amazonlinux-64:2.1.6",type="LINUX_CONTAINER",computeType="BUILD_GENERAL1_SMALL"  --name $PROJECT_NAME

### AWS CodeBuild Console
In the AWS Codebuild console, select **Start build** to deploy BLESS.

A Lambda function named bless_lambda will now be created and be able to sign certficates.

## Create a Testing environment and Use BLESS
Use the bash script in the folder bless_bash named ec2_deploy or follow the step by step instructions. 

If using the bash script, change the variable for AWS_REGION at the tops of the ec2_deploy script if not in region us-east-1.

Running this script will:

- Create a Key Pair.
- Create a new EC2 instance everytime the script is run.
- Configure the EC2 instance to trust the cert.
- Build a BLESS client.
- Log on to the EC2 instance with a new cert.


#### Step by Step Instrutions to Create an EC2 Instance and Configure the Instance to Trust the Certificate.
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
