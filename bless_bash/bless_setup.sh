#!/bin/bash

yum install -y python3 git gcc libffi-devel openssl-devel make zip

pip install awscli

python -m venv venv

source venv/bin/activate

make develop

pip install -e .

cp -r venv/lib/python3.7/site-packages/. aws_lambda_libs

cp -r venv/lib64/python3.7/site-packages/. aws_lambda_libs

#python3 bless_python/bless_deploy.py

