FROM amazonlinux:latest
LABEL Description="Bless Deployment"
MAINTAINER syenna.graham@practicalcode.us


RUN yum install -y python3 git gcc libffi-devel openssl-devel make zip python3-pip 

RUN pip3 install awscli

WORKDIR /bless

COPY . /bless/

RUN python3 -m venv venv

RUN yum install -y python2-pip

RUN source venv/bin/activate &&  make develop

RUN venv/bin/pip install -e .
RUN venv/bin/pip install awscli

RUN cp -r venv/lib/python3.7/site-packages/. aws_lambda_libs

RUN cp -r venv/lib64/python3.7/site-packages/. aws_lambda_libs

ENTRYPOINT ["python3", "/bless/bless_python/bless_deploy.py"]
